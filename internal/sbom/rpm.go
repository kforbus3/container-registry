package sbom

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"

	_ "modernc.org/sqlite"
)

// RPM stores its installed-package set as a set of binary "headers". The
// container for those headers has changed three times, so an image may carry
// any of:
//
//	var/lib/rpm/rpmdb.sqlite   SQLite      rpm >= 4.16 (Fedora 33+, RHEL 9+)
//	var/lib/rpm/Packages       Berkeley DB rpm <= 4.15 (RHEL 7 and 8, UBI 8)
//	var/lib/rpm/Packages.db    ndb         openSUSE / SLE 15
//
// The header format inside is identical in all three, so only the container
// differs. Newer distributions moved the directory to /usr/lib/sysimage/rpm.
var rpmDatabasePaths = []string{
	"var/lib/rpm/rpmdb.sqlite",
	"usr/lib/sysimage/rpm/rpmdb.sqlite",
	"var/lib/rpm/Packages",
	"usr/lib/sysimage/rpm/Packages",
	"var/lib/rpm/Packages.db",
	"usr/lib/sysimage/rpm/Packages.db",
}

func isRPMDatabase(name string) bool {
	for _, p := range rpmDatabasePaths {
		if name == p {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- header

// RPM header tags. Only the ones needed to identify a package are listed.
const (
	tagName      = 1000
	tagVersion   = 1001
	tagRelease   = 1002
	tagEpoch     = 1003
	tagLicense   = 1014
	tagArch      = 1022
	tagSourceRPM = 1044
)

// RPM header data types.
const (
	typeInt32       = 4
	typeString      = 6
	typeStringArray = 8
	typeI18NString  = 9
)

// rpmHeaderMagic prefixes a header region. Headers stored inside a database
// usually omit it, so its presence is detected rather than required.
var rpmHeaderMagic = []byte{0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00}

// parseRPMHeader decodes one RPM header blob.
//
// Layout: a 4-byte count of index entries and a 4-byte data-store length, then
// that many 16-byte index entries (tag, type, offset, count), then the data
// store the offsets point into. Everything is big endian.
func parseRPMHeader(blob []byte) (pkg, bool) {
	if len(blob) >= 8 && bytes.Equal(blob[:8], rpmHeaderMagic) {
		blob = blob[8:]
	}
	if len(blob) < 8 {
		return pkg{}, false
	}
	indexCount := binary.BigEndian.Uint32(blob[0:4])
	dataLen := binary.BigEndian.Uint32(blob[4:8])

	// Reject implausible values before doing any arithmetic on them: this data
	// comes straight out of an image and cannot be trusted.
	const maxIndexEntries = 1 << 20
	const maxDataLen = 256 << 20
	if indexCount == 0 || indexCount > maxIndexEntries || dataLen > maxDataLen {
		return pkg{}, false
	}
	indexStart := 8
	dataStart := indexStart + int(indexCount)*16
	if dataStart < indexStart || dataStart+int(dataLen) > len(blob) {
		return pkg{}, false
	}
	data := blob[dataStart : dataStart+int(dataLen)]

	var p pkg
	var version, release string
	for i := 0; i < int(indexCount); i++ {
		entry := blob[indexStart+i*16 : indexStart+(i+1)*16]
		tag := binary.BigEndian.Uint32(entry[0:4])
		typ := binary.BigEndian.Uint32(entry[4:8])
		offset := binary.BigEndian.Uint32(entry[8:12])

		switch tag {
		case tagName, tagVersion, tagRelease, tagLicense, tagArch, tagSourceRPM:
			s, ok := rpmString(data, offset, typ)
			if !ok {
				continue
			}
			switch tag {
			case tagName:
				p.Name = s
			case tagVersion:
				version = s
			case tagRelease:
				release = s
			case tagLicense:
				p.License = s
			case tagArch:
				p.Arch = s
			case tagSourceRPM:
				p.Source = s
			}
		case tagEpoch:
			if n, ok := rpmInt32(data, offset, typ); ok && n > 0 {
				p.Epoch = strconv.FormatInt(int64(n), 10)
			}
		}
	}
	if p.Name == "" {
		return pkg{}, false
	}
	// A package URL names an RPM by version-release.
	p.Version = version
	if release != "" {
		p.Version = version + "-" + release
	}
	p.Ecosystem = "rpm"
	return p, true
}

func rpmString(data []byte, offset, typ uint32) (string, bool) {
	if typ != typeString && typ != typeI18NString && typ != typeStringArray {
		return "", false
	}
	if offset >= uint32(len(data)) {
		return "", false
	}
	rest := data[offset:]
	end := bytes.IndexByte(rest, 0)
	if end < 0 {
		return "", false
	}
	return string(rest[:end]), true
}

func rpmInt32(data []byte, offset, typ uint32) (int32, bool) {
	if typ != typeInt32 || offset+4 > uint32(len(data)) {
		return 0, false
	}
	return int32(binary.BigEndian.Uint32(data[offset : offset+4])), true
}

// ---------------------------------------------------------------- dispatch

// parseRPMDB extracts packages from whichever database container was found.
func parseRPMDB(path string, content []byte) []pkg {
	var headers [][]byte
	switch {
	case bytes.HasPrefix(content, []byte("SQLite format 3\x00")):
		headers = rpmHeadersFromSQLite(content)
	case looksLikeNDB(content):
		headers = rpmHeadersFromNDB(content)
	default:
		headers = rpmHeadersFromBDB(content)
	}

	out := make([]pkg, 0, len(headers))
	seen := make(map[string]bool, len(headers))
	for _, h := range headers {
		p, ok := parseRPMHeader(h)
		if !ok {
			continue
		}
		key := p.Name + "\x00" + p.Version + "\x00" + p.Arch
		if seen[key] {
			continue
		}
		seen[key] = true
		p.Source = path
		out = append(out, p)
	}
	return out
}

// ---------------------------------------------------------------- sqlite backend

// rpmHeadersFromSQLite reads the blob column of the Packages table. The file
// has to reach the driver as a path, so it is staged in a temporary file and
// opened read-only.
func rpmHeadersFromSQLite(content []byte) [][]byte {
	f, err := os.CreateTemp("", "rpmdb-*.sqlite")
	if err != nil {
		return nil
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(content); err != nil {
		f.Close()
		return nil
	}
	if err := f.Close(); err != nil {
		return nil
	}

	// immutable=1 tells SQLite the file cannot change underneath it, which also
	// stops it creating -wal/-shm siblings next to our temporary file.
	dsn := fmt.Sprintf("file:%s?mode=ro&immutable=1", f.Name())
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil
	}
	defer database.Close()

	rows, err := database.Query(`SELECT blob FROM Packages`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out [][]byte
	for rows.Next() {
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			return out
		}
		out = append(out, blob)
	}
	return out
}

// ---------------------------------------------------------------- berkeley db backend

// Berkeley DB page types and magic numbers.
const (
	bdbHashMagic      = 0x00061561
	bdbPageTypeHash   = 8
	bdbPageTypeHashUn = 13
	bdbPageTypeOver   = 7

	bdbPageHeaderSize = 26
	bdbHashOffPage    = 3 // HOFFPAGE: the value lives on overflow pages
	bdbHashKeyData    = 1 // HKEYDATA: the value is inline
)

// rpmHeadersFromBDB walks a Berkeley DB hash database and returns the data
// half of every key/data pair, which is an RPM header.
func rpmHeadersFromBDB(content []byte) [][]byte {
	if len(content) < 72 {
		return nil
	}
	// The metadata page records the byte order via the magic number, then the
	// page size and the highest page number in use.
	var order binary.ByteOrder = binary.LittleEndian
	magic := binary.LittleEndian.Uint32(content[12:16])
	if magic != bdbHashMagic {
		if binary.BigEndian.Uint32(content[12:16]) != bdbHashMagic {
			return nil
		}
		order = binary.BigEndian
	}
	pageSize := order.Uint32(content[20:24])
	lastPage := order.Uint32(content[32:36])
	if pageSize < bdbPageHeaderSize || pageSize > 1<<20 || pageSize&(pageSize-1) != 0 {
		return nil
	}

	var out [][]byte
	for pgno := uint32(1); pgno <= lastPage; pgno++ {
		start := uint64(pgno) * uint64(pageSize)
		if start+uint64(pageSize) > uint64(len(content)) {
			break
		}
		page := content[start : start+uint64(pageSize)]
		if page[25] != bdbPageTypeHash && page[25] != bdbPageTypeHashUn {
			continue
		}
		entries := order.Uint16(page[20:22])
		// Index entries come in key/data pairs; only the data half is wanted.
		for i := 1; i < int(entries); i += 2 {
			blob := bdbEntry(content, page, order, pageSize, i, int(entries))
			if len(blob) > 0 {
				out = append(out, blob)
			}
		}
	}
	return out
}

// bdbEntry resolves one index entry, following the overflow chain when the
// value was too large to store inline.
func bdbEntry(content, page []byte, order binary.ByteOrder, pageSize uint32, idx, entries int) []byte {
	inpStart := bdbPageHeaderSize + idx*2
	if inpStart+2 > len(page) {
		return nil
	}
	offset := int(order.Uint16(page[inpStart : inpStart+2]))
	if offset <= 0 || offset >= len(page) {
		return nil
	}
	switch page[offset] {
	case bdbHashOffPage:
		// HOFFPAGE: type(1) unused(3) pgno(4) tlen(4)
		if offset+12 > len(page) {
			return nil
		}
		pgno := order.Uint32(page[offset+4 : offset+8])
		total := order.Uint32(page[offset+8 : offset+12])
		return bdbOverflow(content, order, pageSize, pgno, total)

	case bdbHashKeyData:
		// The entry runs from its own offset up to the start of the previous
		// entry, since items are packed from the end of the page downwards.
		end := int(pageSize)
		if idx > 0 {
			prev := bdbPageHeaderSize + (idx-1)*2
			if prev+2 <= len(page) {
				end = int(order.Uint16(page[prev : prev+2]))
			}
		}
		if end <= offset+1 || end > len(page) {
			return nil
		}
		return page[offset+1 : end]
	}
	return nil
}

// bdbOverflow reassembles a value spread across a chain of overflow pages.
func bdbOverflow(content []byte, order binary.ByteOrder, pageSize, pgno, total uint32) []byte {
	const maxOverflowBytes = 64 << 20
	if total == 0 || total > maxOverflowBytes {
		return nil
	}
	out := make([]byte, 0, total)
	// A corrupt chain could loop; the page budget bounds the walk.
	for steps := 0; pgno != 0 && uint32(len(out)) < total && steps < 1<<16; steps++ {
		start := uint64(pgno) * uint64(pageSize)
		if start+uint64(pageSize) > uint64(len(content)) {
			break
		}
		page := content[start : start+uint64(pageSize)]
		if page[25] != bdbPageTypeOver {
			break
		}
		// On an overflow page hf_offset carries the length of this fragment.
		n := int(order.Uint16(page[22:24]))
		if n <= 0 || bdbPageHeaderSize+n > len(page) {
			break
		}
		out = append(out, page[bdbPageHeaderSize:bdbPageHeaderSize+n]...)
		pgno = order.Uint32(page[16:20]) // next_pgno
	}
	if uint32(len(out)) < total {
		return nil
	}
	return out[:total]
}

// ---------------------------------------------------------------- ndb backend

var (
	ndbHeaderMagic = []byte{'R', 'p', 'm', 'P'}
	ndbBlobMagic   = []byte{'B', 'l', 'b', 'S'}
)

func looksLikeNDB(content []byte) bool {
	return len(content) >= 4 && bytes.Equal(content[:4], ndbHeaderMagic)
}

// rpmHeadersFromNDB reads openSUSE's ndb container. Package blobs are prefixed
// with a "BlbS" marker, so the file is walked for those markers and the header
// that follows each one is validated by parsing it. Anchoring on the marker
// keeps this cheap, and a blob that does not parse is simply skipped.
func rpmHeadersFromNDB(content []byte) [][]byte {
	var out [][]byte
	for i := 0; i+16 < len(content); {
		j := bytes.Index(content[i:], ndbBlobMagic)
		if j < 0 {
			break
		}
		pos := i + j
		// The blob header is 4-byte aligned within the file; a marker at an
		// unaligned position is a coincidence inside package data.
		if pos%4 != 0 {
			i = pos + 1
			continue
		}
		// Layout: magic(4) pkgidx(4) tstamp(4) blobtail... the RPM header
		// begins after the fixed prefix. Both observed prefix lengths are
		// tried, and a wrong guess simply fails to parse.
		for _, prefix := range []int{16, 12} {
			start := pos + prefix
			if start >= len(content) {
				continue
			}
			if _, ok := parseRPMHeader(content[start:]); ok {
				out = append(out, content[start:])
				break
			}
		}
		i = pos + 4
	}
	return out
}
