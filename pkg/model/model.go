package model

import (
	"sort"
	"sync"
)

type Package struct {
	PkgKey            int64  // used while inserting into sqlite db
	PkgId             string // package hash -> checksum
	Name              string // name
	Arch              string // architecture
	Version           string // version
	Epoch             string // epoch
	Release           string // release
	Summary           string // summary
	Description       string // description
	Url               string // package homepage
	TimeFile          int64  // mtime of file
	TimeBuild         int64  // build time (from rpm header)
	RpmLicense        string // license
	RpmVendor         string // vendor
	RpmGroup          string // group (one value from /usr/share/doc/rpm-(your_rpm_version)/GROUPS)
	RpmBuildHost      string // hostname of machine which builds the package
	RpmSourceRpm      string // name of srpms
	RpmHeaderStart    int    // start byte of header in rpm
	RpmHeaderEnd      int    // end byte of header in rpm
	RpmPackager       string // packager of package
	SizePackage       int64  // size of rpm package
	SizeInstalled     int64  // size of installed files
	SizeArchive       int64  // size of archive (I have no idea what does it mean)
	LocationHref      string // file location inside repository
	LocationBase      string // location (url) of repository
	ChecksumType      string // type of checksum used ("sha1", "sha256", "md5", ..)
	FilesChecksumType string // type of checksum used for files ("sha1", "sha256", "md5", ..)

	Requires    []Dependency // requires (list of Dependency structs)
	Provides    []Dependency // provides (list of Dependency structs)
	Conflicts   []Dependency // conflicts (list of Dependency structs)
	Obsoletes   []Dependency // obsoletes (list of Dependency structs)
	Suggests    []Dependency // suggests (list of Dependency structs)
	Enhances    []Dependency // enhances (list of Dependency structs)
	Recommends  []Dependency // recommends (list of Dependency structs)
	Supplements []Dependency // supplements (list of Dependency structs)

	Files      []PackageFile    // files in the package (list of PackageFile structs)
	Changelogs []ChangelogEntry // changelogs (list of cr_ChangelogEntry structs)
}

// Dependency Dependency (Provides, Conflicts, Obsoletes, Requires)
type Dependency struct {
	Name    string
	Flags   string
	Epoch   string
	Version string
	Release string
	Pre     bool
}

// ChangelogEntry represents a changelog entry.
type ChangelogEntry struct {
	Author    string // Author of the changelog
	Date      int64  // Date of the changelog - seconds since epoch
	Changelog string // Text of the changelog
}

// PackageFile represents a file in a package.
type PackageFile struct {
	FullPath string // path to file
	Type     string // one of "" (regular file), "dir", "ghost"
	Digest   string // file checksum
}

// EVR represents Epoch-Version-Release
type EVR struct {
	Epoch   string
	Version string
	Release string
}

// NEVR represents Name-Epoch-Version-Release
type NEVR struct {
	Name    string
	Epoch   string
	Version string
	Release string
}

// NEVRA represents Name-Epoch-Version-Release-Architecture
type NEVRA struct {
	Name    string
	Epoch   string
	Version string
	Release string
	Arch    string
}

// ApValueStruct Struct used as value in ap_hashtable
type ApValueStruct struct {
	Flags   string
	Version string
	Pre     bool
}

type DuplicateLocation struct {
	Location string
	Pkg      *Package
}

// XmlStruct holds XML chunks for primary.xml, filelists[_ext].xml and other.xml.
type XmlStruct struct {
	Primary      string // XML chunk for primary.xml
	Filelists    string // XML chunk for filelists.xml
	FilelistsExt string // XML chunk for filelists-ext.xml
	Other        string // XML chunk for other.xml
}

// XMLStructAll holds XML list for primary.xml, filelists[_ext].xml and other.xml.
type XMLStructAll struct {
	MutexPrimary        sync.Mutex
	MutexFilelists      sync.Mutex
	MutexOtherData      sync.Mutex
	MutexFilelistsExt   sync.Mutex
	PrimaryXMLData      // XML chunk for primary.xml
	FilelistsXMLData    // XML chunk for filelists.xml
	OtherXMLData        // XML chunk for other.xml
	FilelistsExtXMLData // XML chunk for filelists-ext.xml
}

func (x *XMLStructAll) SortPackageByTaskID() {
	sort.Slice(x.PrimaryXMLData.PackageList, func(i, j int) bool {
		return x.PrimaryXMLData.PackageList[i].ID < x.PrimaryXMLData.PackageList[j].ID
	})
	sort.Slice(x.FilelistsXMLData.PackageList, func(i, j int) bool {
		return x.FilelistsXMLData.PackageList[i].ID < x.FilelistsXMLData.PackageList[j].ID
	})
	sort.Slice(x.OtherXMLData.PackageList, func(i, j int) bool {
		return x.OtherXMLData.PackageList[i].ID < x.OtherXMLData.PackageList[j].ID
	})
	sort.Slice(x.FilelistsExtXMLData.PackageList, func(i, j int) bool {
		return x.FilelistsExtXMLData.PackageList[i].ID < x.FilelistsExtXMLData.PackageList[j].ID
	})
}

func (x *XMLStructAll) SetPackageNum() {
	x.PrimaryXMLData.PackageNum = len(x.PrimaryXMLData.PackageList)
	x.FilelistsXMLData.PackageNum = len(x.FilelistsXMLData.PackageList)
	x.OtherXMLData.PackageNum = len(x.OtherXMLData.PackageList)
	x.FilelistsExtXMLData.PackageNum = len(x.FilelistsExtXMLData.PackageList)
}
