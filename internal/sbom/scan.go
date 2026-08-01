package sbom

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Limits bound the work a single scan may do, so a hostile or simply enormous
// image cannot exhaust the registry.
type Limits struct {
	// MaxFileBytes caps any single file read out of a layer.
	MaxFileBytes int64
	// MaxDatabaseBytes caps a package database. An RPM database on a full
	// installation runs to tens of megabytes, well past MaxFileBytes.
	MaxDatabaseBytes int64
	// MaxManifestBytes caps one language-package metadata file.
	MaxManifestBytes int64
	// MaxTotalBytes caps the total decompressed bytes read across all layers.
	MaxTotalBytes int64
	// MaxBinaries caps how many executables are inspected for Go build info.
	MaxBinaries int
	// MaxManifests caps how many language-package metadata files are retained.
	// A large node_modules tree can hold tens of thousands.
	MaxManifests int
	// MaxEntries caps how many tar entries are walked.
	MaxEntries int
}

func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:     32 << 20,  // 32 MiB
		MaxDatabaseBytes: 256 << 20, // 256 MiB
		MaxManifestBytes: 1 << 20,   // 1 MiB: a package.json is a few KiB
		MaxTotalBytes:    8 << 30,   // 8 GiB of decompressed content
		MaxBinaries:      256,
		MaxManifests:     20_000,
		MaxEntries:       500_000,
	}
}

var errBudgetExhausted = errors.New("scan budget exhausted")

// fixedFilesOfInterest are the OS package databases and release files, found at
// known absolute paths. Everything else is streamed past.
var fixedFilesOfInterest = map[string]bool{
	"lib/apk/db/installed": true,
	"var/lib/dpkg/status":  true,
	"etc/os-release":       true,
	"usr/lib/os-release":   true,
}

// fileKind classifies a path so the scanner knows what to do with it.
type fileKind int

const (
	kindIgnore   fileKind = iota
	kindOSFile            // a fixed-path OS file: apk/dpkg database or os-release
	kindRPMDB             // an RPM database, in any of its container formats
	kindManifest          // an npm or Python package metadata file
)

func classify(name string) fileKind {
	switch {
	case fixedFilesOfInterest[name]:
		return kindOSFile
	case isRPMDatabase(name):
		return kindRPMDB
	case isNPMManifest(name), isPythonMetadata(name):
		return kindManifest
	}
	return kindIgnore
}

// layerScan is the accumulated view of the filesystem after applying layers in
// order. Only files of interest are retained.
type layerScan struct {
	// files holds fixed-path OS files and RPM databases.
	files map[string][]byte
	// manifests holds language-package metadata, keyed by path so a later
	// layer replaces an earlier one and whiteouts can remove entries.
	manifests map[string][]byte
	binaries  []executable
	limits    Limits

	entries            int
	total              int64
	manifestsTruncated bool
}

// executable is a candidate program buffered for Go build-info extraction.
type executable struct {
	path    string
	content []byte
}

func newLayerScan(l Limits) *layerScan {
	return &layerScan{
		files:     map[string][]byte{},
		manifests: map[string][]byte{},
		limits:    l,
	}
}

// Result carries everything a scan learned about an image.
type Result struct {
	Packages []pkg
	Distro   string
	// ManifestsTruncated reports that the language-package cap was reached, so
	// the component list is incomplete. It is surfaced in the document rather
	// than silently under-reporting.
	ManifestsTruncated bool
}

// Scan reads image layers in order and returns the packages found. Layers must
// be supplied lowest-first, as they appear in the manifest.
func Scan(layers []LayerSource, l Limits) (*Result, error) {
	s := newLayerScan(l)
	for i, layer := range layers {
		if err := s.applyLayer(layer); err != nil {
			if errors.Is(err, errBudgetExhausted) {
				break
			}
			return nil, fmt.Errorf("layer %d (%s): %w", i, layer.Digest, err)
		}
	}

	res := &Result{
		Distro:             distroFrom(string(s.files["etc/os-release"]) + "\n" + string(s.files["usr/lib/os-release"])),
		ManifestsTruncated: s.manifestsTruncated,
	}

	if db, ok := s.files["lib/apk/db/installed"]; ok {
		res.Packages = append(res.Packages, parseAPK(db)...)
	}
	if db, ok := s.files["var/lib/dpkg/status"]; ok {
		res.Packages = append(res.Packages, parseDpkg(db)...)
	}
	// An image carries at most one RPM database, but the path it lives at
	// varies by distribution and release.
	for _, name := range rpmDatabasePaths {
		if db, ok := s.files[name]; ok && len(db) > 0 {
			if found := parseRPMDB(name, db); len(found) > 0 {
				res.Packages = append(res.Packages, found...)
				break
			}
		}
	}
	for path, content := range s.manifests {
		if isNPMManifest(path) {
			res.Packages = append(res.Packages, parseNPM(path, content)...)
		} else {
			res.Packages = append(res.Packages, parsePython(path, content)...)
		}
	}
	for _, b := range s.binaries {
		res.Packages = append(res.Packages, parseGoBinary(b.path, b.content)...)
	}
	return res, nil
}

// LayerSource supplies one layer's bytes.
type LayerSource struct {
	Digest    string
	MediaType string
	Open      func() (io.ReadCloser, error)
}

// compressed reports how the layer body is encoded.
func (l LayerSource) compression() string {
	switch {
	case strings.HasSuffix(l.MediaType, "+gzip"), strings.HasSuffix(l.MediaType, ".tar.gzip"):
		return "gzip"
	case strings.HasSuffix(l.MediaType, "+zstd"):
		return "zstd"
	default:
		return "none"
	}
}

func (s *layerScan) applyLayer(layer LayerSource) error {
	rc, err := layer.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	var body io.Reader = rc
	switch layer.compression() {
	case "gzip":
		zr, err := gzip.NewReader(rc)
		if err != nil {
			// Some layers are declared gzip but stored plain; fall back rather
			// than discarding the layer.
			return nil
		}
		defer zr.Close()
		body = zr
	case "zstd":
		zr, err := zstd.NewReader(rc, zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil
		}
		defer zr.Close()
		body = zr
	}

	tr := tar.NewReader(body)
	for {
		if s.entries >= s.limits.MaxEntries || s.total >= s.limits.MaxTotalBytes {
			return errBudgetExhausted
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			// A truncated or malformed layer yields whatever was read so far.
			return nil
		}
		s.entries++

		name := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		if name == "." || name == "/" {
			continue
		}
		name = strings.TrimPrefix(name, "/")

		// Whiteouts delete paths contributed by lower layers.
		base := path.Base(name)
		if strings.HasPrefix(base, ".wh.") {
			s.applyWhiteout(name, base)
			continue
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if err := s.consider(name, hdr, tr); err != nil {
			return err
		}
	}
}

func (s *layerScan) applyWhiteout(name, base string) {
	dir := path.Dir(name)
	if base == ".wh..wh..opq" {
		// Opaque whiteout: everything below dir from lower layers is hidden.
		for p := range s.files {
			if strings.HasPrefix(p, dir+"/") {
				delete(s.files, p)
			}
		}
		for p := range s.manifests {
			if strings.HasPrefix(p, dir+"/") {
				delete(s.manifests, p)
			}
		}
		return
	}
	target := path.Join(dir, strings.TrimPrefix(base, ".wh."))
	delete(s.files, target)
	delete(s.manifests, target)
	// A whited-out directory takes the metadata beneath it with it.
	for p := range s.manifests {
		if strings.HasPrefix(p, target+"/") {
			delete(s.manifests, p)
		}
	}
}

func (s *layerScan) consider(name string, hdr *tar.Header, tr io.Reader) error {
	switch classify(name) {
	case kindOSFile:
		b, err := s.readBounded(tr, hdr.Size, s.limits.MaxFileBytes)
		if err != nil {
			return err
		}
		s.files[name] = b // a later layer replaces the same path

	case kindRPMDB:
		b, err := s.readBounded(tr, hdr.Size, s.limits.MaxDatabaseBytes)
		if err != nil {
			return err
		}
		s.files[name] = b

	case kindManifest:
		if len(s.manifests) >= s.limits.MaxManifests {
			s.manifestsTruncated = true
			return nil
		}
		b, err := s.readBounded(tr, hdr.Size, s.limits.MaxManifestBytes)
		if err != nil {
			return err
		}
		s.manifests[name] = b

	default:
		if !s.isCandidateBinary(name, hdr) {
			return nil
		}
		b, err := s.readBounded(tr, hdr.Size, s.limits.MaxFileBytes)
		if err != nil {
			return err
		}
		if looksExecutable(b) {
			s.binaries = append(s.binaries, executable{path: name, content: b})
		}
	}
	return nil
}

// isCandidateBinary keeps the Go build-info scan bounded: only executable
// regular files of a plausible size, and only up to a fixed count.
func (s *layerScan) isCandidateBinary(name string, hdr *tar.Header) bool {
	if len(s.binaries) >= s.limits.MaxBinaries {
		return false
	}
	if hdr.FileInfo().Mode()&0o111 == 0 {
		return false
	}
	if hdr.Size < 1<<20 || hdr.Size > s.limits.MaxFileBytes {
		// Go binaries are never tiny, and anything huge is not worth buffering.
		return false
	}
	// Skip obvious shared libraries and scripts.
	if strings.HasSuffix(name, ".so") || strings.Contains(name, ".so.") {
		return false
	}
	return true
}

func (s *layerScan) readBounded(r io.Reader, size, max int64) ([]byte, error) {
	if size > max {
		size = max
	}
	buf := make([]byte, 0, min64(size, 1<<20))
	n, err := io.Copy(&byteSink{buf: &buf, max: max}, io.LimitReader(r, size))
	s.total += n
	if err != nil {
		return nil, nil // treat an unreadable entry as absent
	}
	return buf, nil
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// byteSink appends into a slice while enforcing a hard cap.
type byteSink struct {
	buf *[]byte
	max int64
}

func (w *byteSink) Write(p []byte) (int, error) {
	if int64(len(*w.buf))+int64(len(p)) > w.max {
		return 0, errBudgetExhausted
	}
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}

// looksExecutable checks for an ELF or Mach-O magic number, so text files that
// merely carry the execute bit are not buffered through the Go parser.
func looksExecutable(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch {
	case b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F':
		return true // ELF
	case b[0] == 0xcf && b[1] == 0xfa && b[2] == 0xed && b[3] == 0xfe:
		return true // Mach-O 64-bit little endian
	case b[0] == 0xfe && b[1] == 0xed && b[2] == 0xfa && b[3] == 0xcf:
		return true // Mach-O 64-bit big endian
	}
	return false
}
