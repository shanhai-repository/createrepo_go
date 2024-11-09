package constant

import "github.com/sassoftware/go-rpmutils"

const (
	DefaultChecksum       = ChecksumSHA256
	DefaultRepomdChecksum = ChecksumSHA256
	DefaultWorkers        = 5
	DefaultChangelogLimit = 10
)

// ChecksumType is an enumeration of supported checksum types.
// SHA is considered equivalent to SHA1 for compatibility with original createrepo.
type ChecksumType int

const (
	ChecksumUnknown  ChecksumType = iota // 0, Unknown checksum
	ChecksumMD5                          // 1, MD5 checksum; legacy
	ChecksumSHA                          // 2, SHA checksum; legacy
	ChecksumSHA1                         // 3, SHA1 checksum; legacy
	ChecksumSHA224                       // 4, SHA224 checksum
	ChecksumSHA256                       // 5, SHA256 checksum
	ChecksumSHA384                       // 6, SHA384 checksum
	ChecksumSHA512                       // 7, SHA512 checksum
	ChecksumSentinel                     // 8, sentinel of the list
)

// ChecksumName returns the string representation of a ChecksumType.
func ChecksumName(checksumType ChecksumType) string {
	switch checksumType {
	case ChecksumUnknown:
		return "Unknown checksum"
	case ChecksumMD5: // legacy
		return "md5"
	case ChecksumSHA: // legacy
		return "sha"
	case ChecksumSHA1: // legacy
		return "sha1"
	case ChecksumSHA224:
		return "sha224"
	case ChecksumSHA256:
		return "sha256"
	case ChecksumSHA384:
		return "sha384"
	case ChecksumSHA512:
		return "sha512"
	default:
		return ""
	}
}

// CompressionType represents the type of compression.
type CompressionType int

// Define compression types as constants.
const (
	CR_CW_AUTO_DETECT_COMPRESSION CompressionType = iota // Autodetection
	CR_CW_UNKNOWN_COMPRESSION                            // Unknown compression
	CR_CW_NO_COMPRESSION                                 // No compression
	CR_CW_GZ_COMPRESSION                                 // Gzip compression
	CR_CW_BZ2_COMPRESSION                                // BZip2 compression
	CR_CW_XZ_COMPRESSION                                 // XZ compression
	CR_CW_ZCK_COMPRESSION                                // ZCK compression
	CR_CW_ZSTD_COMPRESSION                               // ZSTD compression
	CR_CW_COMPRESSION_SENTINEL                           // Sentinel of the list
)

const DefaultCompressionType = CR_CW_ZSTD_COMPRESSION

// CompressionSuffix returns the file suffix for a given compression type.
func CompressionSuffix(comtype CompressionType) string {
	switch comtype {
	case CR_CW_GZ_COMPRESSION:
		return ".gz"
	case CR_CW_BZ2_COMPRESSION:
		return ".bz2"
	case CR_CW_XZ_COMPRESSION:
		return ".xz"
	case CR_CW_ZCK_COMPRESSION:
		return ".zck"
	case CR_CW_ZSTD_COMPRESSION:
		return ".zst"
	default:
		return ""
	}
}

type DepType int

const (
	DEP_PROVIDES DepType = iota
	DEP_CONFLICTS
	DEP_OBSOLETES
	DEP_REQUIRES
	DEP_SUGGESTS
	DEP_ENHANCES
	DEP_RECOMMENDS
	DEP_SUPPLEMENTS
	// ENABLE_LEGACY_WEAKDEPS
	DEP_OLDSUGGESTS
	DEP_OLDENHANCES
	// End of enum
	DEP_SENTINEL
)

type DepItem struct {
	Type       DepType
	NameTag    int
	FlagsTag   int
	VersionTag int
}

var DepItems = []DepItem{
	{DEP_PROVIDES, rpmutils.PROVIDENAME, rpmutils.PROVIDEFLAGS, rpmutils.PROVIDEVERSION},
	{DEP_CONFLICTS, rpmutils.CONFLICTNAME, rpmutils.CONFLICTFLAGS, rpmutils.CONFLICTVERSION},
	{DEP_OBSOLETES, rpmutils.OBSOLETENAME, rpmutils.OBSOLETEFLAGS, rpmutils.OBSOLETEVERSION},
	{DEP_REQUIRES, rpmutils.REQUIRENAME, rpmutils.REQUIREFLAGS, rpmutils.REQUIREVERSION},
	// RPM_WEAK_DEPS_SUPPORT
	{DEP_SUGGESTS, rpmutils.SUGGESTNAME, rpmutils.SUGGESTFLAGS, rpmutils.SUGGESTVERSION},
	{DEP_ENHANCES, rpmutils.ENHANCENAME, rpmutils.ENHANCEFLAGS, rpmutils.ENHANCEVERSION},
	{DEP_RECOMMENDS, rpmutils.RECOMMENDNAME, rpmutils.RECOMMENDFLAGS, rpmutils.RECOMMENDVERSION},
	{DEP_SUPPLEMENTS, rpmutils.SUPPLEMENTNAME, rpmutils.SUPPLEMENTFLAGS, rpmutils.SUPPLEMENTVERSION},
	// ENABLE_LEGACY_WEAKDEPS
	{DEP_OLDSUGGESTS, rpmutils.OLDSUGGESTSNAME, rpmutils.OLDSUGGESTSFLAGS, rpmutils.OLDSUGGESTSVERSION},
	{DEP_OLDENHANCES, rpmutils.OLDENHANCESNAME, rpmutils.OLDENHANCESFLAGS, rpmutils.OLDENHANCESVERSION},
	// End of list
	{DEP_SENTINEL, 0, 0, 0},
}

// RPMSENSE_STRONG ENABLE_LEGACY_WEAKDEPS
const RPMSENSE_STRONG = 1 << 27

// RPMSENSE_MISSINGOK ENABLE_LEGACY_WEAKDEPS
const RPMSENSE_MISSINGOK = 1 << 19

const (
	// Default namespace for primary.xml
	CR_XML_COMMON_NS = "http://linux.duke.edu/metadata/common"
	// Default namespace for filelists.xml
	CR_XML_FILELISTS_NS = "http://linux.duke.edu/metadata/filelists"
	// Default namespace for filelists-ext.xml
	CR_XML_FILELISTS_EXT_NS = "http://linux.duke.edu/metadata/filelists-ext"
	// Default namespace for other.xml
	CR_XML_OTHER_NS = "http://linux.duke.edu/metadata/other"
	// Default namespace for repomd.xml
	CR_XML_REPOMD_NS = "http://linux.duke.edu/metadata/repo"
	// Namespace for rpm (used in primary.xml and repomd.xml)
	CR_XML_RPM_NS = "http://linux.duke.edu/metadata/rpm"
)

type RepomdType string

const (
	LocationHrefPrefix                = "repodata/"
	RepomdTypePrimary      RepomdType = "primary"
	RepomdTypeFilelists    RepomdType = "filelists"
	RepomdTypeOther        RepomdType = "other"
	RepomdTypeFilelistsExt RepomdType = "filelists-ext"
)
