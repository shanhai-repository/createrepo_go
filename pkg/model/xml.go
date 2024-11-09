package model

import "encoding/xml"

// ========== primary.xml ==========

type PrimaryXMLData struct {
	XMLName     xml.Name          `xml:"metadata"`
	Xmlns       string            `xml:"xmlns,attr"`
	XmlnsRPM    string            `xml:"xmlns:rpm,attr"`
	PackageNum  int               `xml:"packages,attr"`
	PackageList []*PrimaryPackage `xml:"package"`
}

type PrimaryPackage struct {
	ID          int64    `xml:"-"`
	Type        string   `xml:"type,attr"`
	Name        string   `xml:"name"`
	Arch        string   `xml:"arch"`
	Version     Version  `xml:"version"`
	Checksum    Checksum `xml:"checksum"`
	Summary     string   `xml:"summary"`
	Description string   `xml:"description"`
	Packager    string   `xml:"packager"`
	URL         string   `xml:"url"`
	Time        Time     `xml:"time"`
	Size        Size     `xml:"size"`
	Location    Location `xml:"location"`
	Format      Format   `xml:"format"`
}

type Version struct {
	Epoch string `xml:"epoch,attr"`
	Ver   string `xml:"ver,attr"`
	Rel   string `xml:"rel,attr"`
}

type Checksum struct {
	Type  string `xml:"type,attr"`
	PkgID string `xml:"pkgid,attr,omitempty"`
	Value string `xml:",chardata"`
}

type Time struct {
	File  string `xml:"file,attr"`
	Build string `xml:"build,attr"`
}

type Size struct {
	Package   string `xml:"package,attr"`
	Installed string `xml:"installed,attr"`
	Archive   string `xml:"archive,attr"`
}

type Location struct {
	Href    string `xml:"href,attr"`
	XMLBase string `xml:"xml:base,attr,omitempty"`
}

type Format struct {
	License     string        `xml:"rpm:license"`
	Vendor      string        `xml:"rpm:vendor"`
	Group       string        `xml:"rpm:group"`
	BuildHost   string        `xml:"rpm:buildhost"`
	SourceRPM   string        `xml:"rpm:sourcerpm"`
	HeaderRange HeaderRange   `xml:"rpm:header-range"`
	Provides    *DepEntryList `xml:"rpm:provides,omitempty"`
	Conflicts   *DepEntryList `xml:"rpm:conflicts,omitempty"`
	Obsoletes   *DepEntryList `xml:"rpm:obsoletes,omitempty"`
	Requires    *DepEntryList `xml:"rpm:requires,omitempty"`
	Suggests    *DepEntryList `xml:"rpm:suggests,omitempty"`
	Enhances    *DepEntryList `xml:"rpm:enhances,omitempty"`
	Recommends  *DepEntryList `xml:"rpm:recommends,omitempty"`
	Supplements *DepEntryList `xml:"rpm:supplements,omitempty"`
	Files       []*File       `xml:"file,omitempty"`
}

type HeaderRange struct {
	Start string `xml:"start,attr"`
	End   string `xml:"end,attr"`
}

type DepEntryList struct {
	Entries []DepEntry `xml:"rpm:entry"`
}

type DepEntry struct {
	Name  string `xml:"name,attr"`
	Flags string `xml:"flags,attr,omitempty"`
	Epoch string `xml:"epoch,attr,omitempty"`
	Ver   string `xml:"ver,attr,omitempty"`
	Rel   string `xml:"rel,attr,omitempty"`
	Pre   string `xml:"pre,attr,omitempty"`
}

type File struct {
	Type  string `xml:"type,attr,omitempty"`
	Hash  string `xml:"hash,attr,omitempty"`
	Value string `xml:",chardata"`
}

// ========== filelists.xml ==========

// FilelistsXMLData represents the root element of the XML.
type FilelistsXMLData struct {
	XMLName     xml.Name            `xml:"filelists"`
	Xmlns       string              `xml:"xmlns,attr"`
	PackageNum  int                 `xml:"packages,attr"`
	PackageList []*FilelistsPackage `xml:"package"`
}

// ========== filelists-ext.xml ==========

// FilelistsExtXMLData represents the root element of the XML.
type FilelistsExtXMLData struct {
	XMLName     xml.Name            `xml:"filelists-ext"`
	Xmlns       string              `xml:"xmlns,attr"`
	PackageNum  int                 `xml:"packages,attr"`
	PackageList []*FilelistsPackage `xml:"package"`
}

// FilelistsPackage represents each package element in the XML.
type FilelistsPackage struct {
	ID       int64              `xml:"-"`
	PkgID    string             `xml:"pkgid,attr"`
	Name     string             `xml:"name,attr"`
	Arch     string             `xml:"arch,attr"`
	Version  Version            `xml:"version"`
	Checksum *FilelistsChecksum `xml:"checksum,omitempty"`
	File     []*File            `xml:"file"`
}

type FilelistsChecksum struct {
	Type string `xml:"type,attr"`
}

// ========== other.xml ==========

type OtherXMLData struct {
	XMLName     xml.Name        `xml:"otherdata"`
	Xmlns       string          `xml:"xmlns,attr"`
	PackageNum  int             `xml:"packages,attr"`
	PackageList []*OtherPackage `xml:"package"`
}

type OtherPackage struct {
	ID        int64        `xml:"-"`
	PkgID     string       `xml:"pkgid,attr"`
	Name      string       `xml:"name,attr"`
	Arch      string       `xml:"arch,attr"`
	Version   Version      `xml:"version"`
	Changelog []*Changelog `xml:"changelog,omitempty"`
}

type Changelog struct {
	Author  string `xml:"author,attr"`
	Date    string `xml:"date,attr"`
	Content string `xml:",chardata"`
}

// ========== repomd.xml ==========

type Repomd struct {
	XMLName  xml.Name        `xml:"repomd"`
	Xmlns    string          `xml:"xmlns,attr"`
	XmlnsRpm string          `xml:"xmlns:rpm,attr"`
	Revision string          `xml:"revision"`
	Data     []*RepomdRecord `xml:"data"`
}

type RepomdRecord struct {
	Type         string   `xml:"type,attr"`
	Checksum     Checksum `xml:"checksum"`
	OpenChecksum Checksum `xml:"open-checksum"`
	Location     Location `xml:"location"`
	Timestamp    int64    `xml:"timestamp"`
	Size         int64    `xml:"size"`
	OpenSize     int64    `xml:"open-size"`
}
