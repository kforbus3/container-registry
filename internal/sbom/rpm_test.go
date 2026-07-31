package sbom

import (
	"encoding/binary"
	"testing"
)

// ---------------------------------------------------------------- fixtures

// rpmField describes one entry to encode into a synthetic header.
type rpmField struct {
	tag   uint32
	typ   uint32
	value any // string or int32
}

// buildRPMHeader encodes fields into the on-disk RPM header layout: a count of
// index entries, a data-store length, the fixed-size index, then the data.
func buildRPMHeader(withMagic bool, fields ...rpmField) []byte {
	var index, data []byte
	for _, f := range fields {
		offset := uint32(len(data))
		count := uint32(1)
		switch v := f.value.(type) {
		case string:
			data = append(data, []byte(v)...)
			data = append(data, 0)
		case int32:
			// Integers are aligned to their own width in a real header; the
			// parser reads by offset, so encoding them packed is still valid.
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(v))
			data = append(data, b[:]...)
		}
		var entry [16]byte
		binary.BigEndian.PutUint32(entry[0:4], f.tag)
		binary.BigEndian.PutUint32(entry[4:8], f.typ)
		binary.BigEndian.PutUint32(entry[8:12], offset)
		binary.BigEndian.PutUint32(entry[12:16], count)
		index = append(index, entry[:]...)
	}

	var out []byte
	if withMagic {
		out = append(out, rpmHeaderMagic...)
	}
	var prefix [8]byte
	binary.BigEndian.PutUint32(prefix[0:4], uint32(len(fields)))
	binary.BigEndian.PutUint32(prefix[4:8], uint32(len(data)))
	out = append(out, prefix[:]...)
	out = append(out, index...)
	out = append(out, data...)
	return out
}

func sampleHeader(name, version, release, arch string, epoch int32) []byte {
	fields := []rpmField{
		{tagName, typeString, name},
		{tagVersion, typeString, version},
		{tagRelease, typeString, release},
		{tagArch, typeString, arch},
		{tagLicense, typeString, "GPLv2+"},
	}
	if epoch > 0 {
		fields = append(fields, rpmField{tagEpoch, typeInt32, epoch})
	}
	return buildRPMHeader(false, fields...)
}

// ---------------------------------------------------------------- header

func TestParseRPMHeader(t *testing.T) {
	blob := sampleHeader("bash", "5.1.8", "9.el9", "x86_64", 0)
	p, ok := parseRPMHeader(blob)
	if !ok {
		t.Fatal("a well-formed header was rejected")
	}
	if p.Name != "bash" {
		t.Errorf("name = %q", p.Name)
	}
	// A package URL identifies an RPM by version-release, not version alone.
	if p.Version != "5.1.8-9.el9" {
		t.Errorf("version = %q, want the version-release form", p.Version)
	}
	if p.Arch != "x86_64" || p.License != "GPLv2+" || p.Ecosystem != "rpm" {
		t.Errorf("unexpected package %+v", p)
	}
	if want := "pkg:rpm/rhel-9/bash@5.1.8-9.el9?arch=x86_64"; p.purl("rhel-9") != want {
		t.Errorf("purl = %q, want %q", p.purl("rhel-9"), want)
	}
}

func TestParseRPMHeaderEpochAndMagic(t *testing.T) {
	// Epoch is carried as a qualifier rather than folded into the version.
	blob := sampleHeader("tzdata", "2024a", "1.el9", "noarch", 2)
	p, ok := parseRPMHeader(blob)
	if !ok {
		t.Fatal("header with an epoch was rejected")
	}
	if p.Epoch != "2" {
		t.Fatalf("epoch = %q, want 2", p.Epoch)
	}
	if want := "pkg:rpm/rhel-9/tzdata@2024a-1.el9?arch=noarch&epoch=2"; p.purl("rhel-9") != want {
		t.Errorf("purl = %q, want %q", p.purl("rhel-9"), want)
	}

	// Some headers carry the 8-byte region magic; it must be tolerated.
	withMagic := buildRPMHeader(true, rpmField{tagName, typeString, "zlib"},
		rpmField{tagVersion, typeString, "1.2.11"}, rpmField{tagRelease, typeString, "40.el9"})
	if p, ok := parseRPMHeader(withMagic); !ok || p.Name != "zlib" {
		t.Fatalf("header with magic prefix: ok=%v pkg=%+v", ok, p)
	}
}

// A header is attacker-controlled data; malformed input must be rejected
// rather than panic or read out of bounds.
func TestParseRPMHeaderRejectsMalformed(t *testing.T) {
	valid := sampleHeader("bash", "5.1.8", "9.el9", "x86_64", 0)

	cases := map[string][]byte{
		"empty":            {},
		"truncated prefix": valid[:4],
		"truncated index":  valid[:12],
		"no name tag": buildRPMHeader(false,
			rpmField{tagVersion, typeString, "1.0"}),
		"absurd index count": func() []byte {
			b := append([]byte(nil), valid...)
			binary.BigEndian.PutUint32(b[0:4], 0xFFFFFFFF)
			return b
		}(),
		"absurd data length": func() []byte {
			b := append([]byte(nil), valid...)
			binary.BigEndian.PutUint32(b[4:8], 0xFFFFFFFF)
			return b
		}(),
		"offset past data": func() []byte {
			b := append([]byte(nil), valid...)
			binary.BigEndian.PutUint32(b[16:20], 0xFFFF) // first entry's offset
			return b
		}(),
	}
	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			// The only requirement is that it returns rather than panics; a
			// header missing a name must additionally be reported invalid.
			if p, ok := parseRPMHeader(blob); ok && p.Name == "" {
				t.Fatal("accepted a header with no package name")
			}
		})
	}
}

// ---------------------------------------------------------------- berkeley db

// buildBDB encodes headers into a minimal Berkeley DB hash file: a metadata
// page followed by hash pages holding key/data pairs.
func buildBDB(t *testing.T, pageSize int, headers [][]byte) []byte {
	t.Helper()
	pages := [][]byte{}

	// Metadata page: magic at 12, page size at 20, last page number at 32.
	meta := make([]byte, pageSize)
	binary.LittleEndian.PutUint32(meta[12:16], bdbHashMagic)
	binary.LittleEndian.PutUint32(meta[20:24], uint32(pageSize))
	pages = append(pages, meta)

	for i, h := range headers {
		page := make([]byte, pageSize)
		page[25] = bdbPageTypeHash
		// Two entries: a key and its data. Items are packed from the end of the
		// page downwards, so the first item sits at the highest offset and each
		// entry's length is the gap up to the previous one. The index array
		// grows forwards from the page header.
		key := []byte{byte(i + 1), 0, 0, 0}
		keyOffset := pageSize - (len(key) + 1)
		dataOffset := keyOffset - (len(h) + 1)
		if dataOffset <= bdbPageHeaderSize+4 {
			t.Fatalf("header %d does not fit in a %d-byte page", i, pageSize)
		}
		page[keyOffset] = bdbHashKeyData
		copy(page[keyOffset+1:], key)
		page[dataOffset] = bdbHashKeyData
		copy(page[dataOffset+1:], h)

		binary.LittleEndian.PutUint16(page[20:22], 2) // entry count
		binary.LittleEndian.PutUint16(page[bdbPageHeaderSize:], uint16(keyOffset))
		binary.LittleEndian.PutUint16(page[bdbPageHeaderSize+2:], uint16(dataOffset))
		pages = append(pages, page)
	}

	binary.LittleEndian.PutUint32(pages[0][32:36], uint32(len(pages)-1))
	var out []byte
	for _, p := range pages {
		out = append(out, p...)
	}
	return out
}

func TestParseRPMDBBerkeley(t *testing.T) {
	headers := [][]byte{
		sampleHeader("bash", "5.1.8", "9.el9", "x86_64", 0),
		sampleHeader("glibc", "2.34", "100.el9", "x86_64", 0),
		sampleHeader("tzdata", "2024a", "1.el9", "noarch", 2),
	}
	db := buildBDB(t, 4096, headers)

	pkgs := parseRPMDB("var/lib/rpm/Packages", db)
	if len(pkgs) != 3 {
		t.Fatalf("parsed %d packages, want 3: %+v", len(pkgs), pkgs)
	}
	byName := map[string]pkg{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	if got := byName["glibc"].Version; got != "2.34-100.el9" {
		t.Errorf("glibc version = %q", got)
	}
	if got := byName["tzdata"].Epoch; got != "2" {
		t.Errorf("tzdata epoch = %q", got)
	}
	for _, p := range pkgs {
		if p.Ecosystem != "rpm" {
			t.Errorf("%s has ecosystem %q", p.Name, p.Ecosystem)
		}
	}
}

// A value too large for one page is stored on a chain of overflow pages.
func TestParseRPMDBBerkeleyOverflow(t *testing.T) {
	pageSize := 512
	// Pad the header so it cannot fit inline in a 512-byte page.
	big := buildRPMHeader(false,
		rpmField{tagName, typeString, "kernel"},
		rpmField{tagVersion, typeString, "5.14.0"},
		rpmField{tagRelease, typeString, "427.el9"},
		rpmField{tagArch, typeString, "x86_64"},
		rpmField{tagLicense, typeString, string(make([]byte, 600))},
	)

	meta := make([]byte, pageSize)
	binary.LittleEndian.PutUint32(meta[12:16], bdbHashMagic)
	binary.LittleEndian.PutUint32(meta[20:24], uint32(pageSize))

	// Page 1: a hash page whose data entry points at the overflow chain.
	hash := make([]byte, pageSize)
	hash[25] = bdbPageTypeHash
	binary.LittleEndian.PutUint16(hash[20:22], 2)
	keyOffset := pageSize - 8
	dataOffset := pageSize - 20
	hash[keyOffset] = bdbHashKeyData
	hash[dataOffset] = bdbHashOffPage
	binary.LittleEndian.PutUint32(hash[dataOffset+4:], 2)                // first overflow page
	binary.LittleEndian.PutUint32(hash[dataOffset+8:], uint32(len(big))) // total length
	binary.LittleEndian.PutUint16(hash[bdbPageHeaderSize:], uint16(keyOffset))
	binary.LittleEndian.PutUint16(hash[bdbPageHeaderSize+2:], uint16(dataOffset))

	// Pages 2..n: the overflow chain carrying the value.
	chunk := pageSize - bdbPageHeaderSize
	var overflow [][]byte
	for off := 0; off < len(big); off += chunk {
		end := off + chunk
		if end > len(big) {
			end = len(big)
		}
		page := make([]byte, pageSize)
		page[25] = bdbPageTypeOver
		binary.LittleEndian.PutUint16(page[22:24], uint16(end-off)) // fragment length
		copy(page[bdbPageHeaderSize:], big[off:end])
		overflow = append(overflow, page)
	}
	// Link each overflow page to the next.
	for i := range overflow {
		next := uint32(0)
		if i+1 < len(overflow) {
			next = uint32(2 + i + 1)
		}
		binary.LittleEndian.PutUint32(overflow[i][16:20], next)
	}

	binary.LittleEndian.PutUint32(meta[32:36], uint32(1+len(overflow)))
	db := append([]byte{}, meta...)
	db = append(db, hash...)
	for _, p := range overflow {
		db = append(db, p...)
	}

	pkgs := parseRPMDB("var/lib/rpm/Packages", db)
	if len(pkgs) != 1 {
		t.Fatalf("parsed %d packages, want 1 reassembled from overflow pages", len(pkgs))
	}
	if pkgs[0].Name != "kernel" || pkgs[0].Version != "5.14.0-427.el9" {
		t.Fatalf("overflow package = %+v", pkgs[0])
	}
}

func TestParseRPMDBRejectsGarbage(t *testing.T) {
	// Neither SQLite, nor ndb, nor a valid BDB metadata page.
	for _, junk := range [][]byte{
		{},
		[]byte("not a database at all"),
		make([]byte, 4096),
	} {
		if pkgs := parseRPMDB("var/lib/rpm/Packages", junk); len(pkgs) != 0 {
			t.Fatalf("parsed %d packages out of garbage", len(pkgs))
		}
	}
}

func TestRPMDatabasePathsRecognised(t *testing.T) {
	for _, p := range []string{
		"var/lib/rpm/rpmdb.sqlite",
		"var/lib/rpm/Packages",
		"var/lib/rpm/Packages.db",
		"usr/lib/sysimage/rpm/rpmdb.sqlite",
	} {
		if classify(p) != kindRPMDB {
			t.Errorf("%s was not classified as an RPM database", p)
		}
	}
	if classify("var/lib/rpm/README") == kindRPMDB {
		t.Error("an unrelated file under var/lib/rpm was treated as a database")
	}
}
