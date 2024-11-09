package util

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"github.com/klauspost/compress/zstd"
	"github.com/sassoftware/go-rpmutils"
	"github.com/shanhai-repository/createrepo_go/pkg/constant"
	"github.com/shanhai-repository/createrepo_go/pkg/logger"
	"github.com/shanhai-repository/createrepo_go/pkg/model"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// NormalizeDirPath Return path with exactly one trailing '/'
func NormalizeDirPath(path string) string {
	if path == "" {
		return "./"
	}

	// Clean the path using filepath.Clean to remove any redundant separators or . and ..
	normalized := filepath.Clean(path)

	// Ensure the path ends with a single slash unless it's a root directory
	if !strings.HasSuffix(normalized, string(filepath.Separator)) && normalized != "/" {
		normalized += string(filepath.Separator)
	}

	return normalized
}

func IsDir(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return s.IsDir()
}

// PathExists if file or dir exists
func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil // exits
	}
	if os.IsNotExist(err) {
		return false, nil // not exists
	}
	return false, err // error
}

// CopyDir iterate copy directory
func CopyDir(src string, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	err = os.MkdirAll(dst, srcInfo.Mode())
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			err = CopyDir(srcPath, dstPath)
			if err != nil {
				return err
			}
		} else {
			err = CopyFile(srcPath, dstPath)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// CopyFile copies a file from src to dst and attempts to preserve metadata.
func CopyFile(src, dst string) error {
	// Open the source file.
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("could not open source file: %v", err)
	}
	defer sourceFile.Close()

	// Create the destination file.
	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("could not create destination file: %v", err)
	}
	defer destFile.Close()

	// Copy the file contents.
	if _, err = io.Copy(destFile, sourceFile); err != nil {
		return fmt.Errorf("could not copy file contents: %v", err)
	}

	// Close the destination file to flush any pending writes.
	if err = destFile.Close(); err != nil {
		return fmt.Errorf("could not close destination file: %v", err)
	}

	// Attempt to copy metadata including permissions, timestamps, and ownership.
	if err = copyMetadataAndOwnership(src, dst); err != nil {
		return fmt.Errorf("could not copy metadata: %v", err)
	}

	return nil
}

func Contains(slice []string, elem string) bool {
	for _, v := range slice {
		if v == elem {
			return true
		}
	}
	return false
}

// copyMetadataAndOwnership copies file metadata and ownership from src to dst.
func copyMetadataAndOwnership(src, dst string) error {
	// Get file info from the source file.
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("could not get source file info: %v", err)
	}

	// Set file permissions.
	if err = os.Chmod(dst, srcInfo.Mode()); err != nil {
		return fmt.Errorf("could not set file permissions: %v", err)
	}

	// Set file timestamps.
	if err = os.Chtimes(dst, srcInfo.ModTime(), srcInfo.ModTime()); err != nil {
		return fmt.Errorf("could not set file timestamps: %v", err)
	}

	// Attempt to copy ownership (only works if running as root or same user).
	srcSys := srcInfo.Sys().(*syscall.Stat_t)
	if err := os.Chown(dst, int(srcSys.Uid), int(srcSys.Gid)); err != nil {
		return fmt.Errorf("could not change file ownership: %v", err)
	}

	return nil
}

// CrFlagToStr Convert flags from RPM header to a string representation.
func CrFlagToStr(flags uint64) string {
	flags &= 0xf
	switch flags {
	case 0:
		return ""
	case 2:
		return "LT"
	case 4:
		return "GT"
	case 8:
		return "EQ"
	case 10:
		return "LE"
	case 12:
		return "GE"
	default:
		return ""
	}
}

// CrIsPrimary Check if the filename match pattern for primary files (files listed in primary.xml).
func CrIsPrimary(filePath string) bool {
	if strings.HasPrefix(filePath, "/etc/") {
		return true
	}
	if filePath == "/usr/lib/sendmail" {
		return true
	}
	if strings.Contains(filePath, "bin/") {
		return true
	}
	return false
}

// CrCompareDependencyRegex
/* Compares two dependency by name
 * NOTE: The function assume first parts must be same!
 * libc.so.6() < libc.so.6(GLIBC_2.3.4)(64 bit) < libc.so.6(GLIBC_2.4)
 * Returns -1 if first < second, 1 if first > second, and 0 if first == second.
 */
func CrCompareDependencyRegex(dep1, dep2 string) int {
	// get glibc version
	regex := regexp.MustCompile(`\((?i:glibc)_([^)]+)\)`)

	// get version from ( ), like getting 2.3.4 from (GLIBC_2.3.4)
	matches1 := regex.FindStringSubmatch(dep1)
	matches2 := regex.FindStringSubmatch(dep2)

	// if both lack of version
	if len(matches1) == 0 && len(matches2) == 0 {
		return 0
	}

	// if first no version
	if len(matches1) == 0 {
		return -1
	}
	// if second no version
	if len(matches2) == 0 {
		return 1
	}

	// compare both version
	return rpmutils.Vercmp(matches1[1], matches2[1])
}

func PackageNEVRA(pkg *model.Package) string {
	epoch := pkg.Epoch
	if epoch == "" {
		epoch = "0"
	}

	return fmt.Sprintf("%s-%s:%s-%s.%s", pkg.Name, epoch, pkg.Version, pkg.Release, pkg.Arch)
}

func StrToEVR(input string) *model.EVR {
	evr := &model.EVR{}

	if input == "" {
		return evr
	}

	// search epoch
	badEpoch := false
	epochEnd := strings.Index(input, ":")
	if epochEnd != -1 {
		epochStr := input[:epochEnd]
		if _, err := strconv.Atoi(epochStr); err != nil {
			badEpoch = true
			logger.SugarLog.Warnf("The epoch string [%s] isn't an integer: %v", epochStr, err)
		} else {
			evr.Epoch = epochStr
		}
		input = input[epochEnd+1:] // remove epoch part
	}

	if evr.Epoch == "" && !badEpoch {
		// set default unless bad epoch value
		evr.Epoch = "0"
	}

	// search version and release
	versionRelease := strings.SplitN(input, "-", 2)
	if len(versionRelease) > 0 {
		evr.Version = versionRelease[0]
		if len(versionRelease) == 2 {
			evr.Release = versionRelease[1]
		}
	}

	return evr
}

// ChecksumFile return checksum of the filename according to the checkSumType
func ChecksumFile(filename string, checkSumType constant.ChecksumType) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var hasher hash.Hash
	switch checkSumType {
	case constant.ChecksumMD5: //WITH_LEGACY_HASHES
		hasher = md5.New()
		break
	case constant.ChecksumSHA: //WITH_LEGACY_HASHES
		hasher = sha1.New()
		break
	case constant.ChecksumSHA1: //WITH_LEGACY_HASHES
		hasher = sha1.New()
		break
	case constant.ChecksumSHA224:
		hasher = sha256.New224()
		break
	case constant.ChecksumSHA256:
		hasher = sha256.New()
		break
	case constant.ChecksumSHA384:
		hasher = sha512.New384()
		break
	case constant.ChecksumSHA512:
		hasher = sha512.New()
		break
	case constant.ChecksumUnknown:
	default:
		return "", fmt.Errorf("unknown checksum type")
	}
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	sum := hasher.Sum(nil)
	return hex.EncodeToString(sum), nil
}

// HasControlChars checks if a string contains control characters other than tab (9), newline (10), and carriage return (13).
func HasControlChars(str string) bool {
	for i := 0; i < len(str); i++ {
		if str[i] < 32 && str[i] != 9 && str[i] != 10 && str[i] != 13 {
			return true
		}
	}
	return false
}

// DependencyListContainsForbiddenControlChars check if the name, epoch, version, and release in the list of dependencies contain any forbidden control characters.
func DependencyListContainsForbiddenControlChars(dep []model.Dependency) bool {
	var ret bool
	for _, d := range dep {
		if d.Name != "" && HasControlChars(d.Name) {
			logger.SugarLog.Errorf("name %s have forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", d.Name)
			ret = true
			break
		}
		if d.Epoch != "" && HasControlChars(d.Epoch) {
			logger.SugarLog.Errorf("epoch %s have forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", d.Epoch)
			ret = true
			break
		}
		if d.Version != "" && HasControlChars(d.Version) {
			logger.SugarLog.Errorf("version %s have forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", d.Version)
			ret = true
			break
		}
		if d.Release != "" && HasControlChars(d.Release) {
			logger.SugarLog.Errorf("release %s have forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", d.Release)
			ret = true
			break
		}
	}
	return ret
}

func PackageContainsForbiddenControlChars(pkg *model.Package) bool {
	ret := false
	if pkg.Name != "" && HasControlChars(pkg.Name) {
		logger.SugarLog.Errorf("Package name %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", pkg.Name)
		ret = true
		goto gotFailure
	}
	if pkg.Epoch != "" && HasControlChars(pkg.Epoch) {
		logger.SugarLog.Errorf("Package epoch %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", pkg.Name)
		ret = true
		goto gotFailure
	}
	if pkg.Version != "" && HasControlChars(pkg.Version) {
		logger.SugarLog.Errorf("Package version %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", pkg.Name)
		ret = true
		goto gotFailure
	}
	if pkg.Release != "" && HasControlChars(pkg.Release) {
		logger.SugarLog.Errorf("Package release %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", pkg.Name)
		ret = true
		goto gotFailure
	}
	if pkg.Arch != "" && HasControlChars(pkg.Arch) {
		logger.SugarLog.Errorf("Package arch %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", pkg.Name)
		ret = true
		goto gotFailure
	}
	if pkg.Summary != "" && HasControlChars(pkg.Summary) {
		logger.SugarLog.Errorf("Package summary %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", pkg.Name)
		ret = true
		goto gotFailure
	}
	if pkg.Description != "" && HasControlChars(pkg.Description) {
		logger.SugarLog.Errorf("Package description %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", pkg.Name)
		ret = true
		goto gotFailure
	}
	if pkg.Url != "" && HasControlChars(pkg.Url) {
		logger.SugarLog.Errorf("Package url %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", pkg.Name)
		ret = true
		goto gotFailure
	}
	if pkg.RpmLicense != "" && HasControlChars(pkg.RpmLicense) {
		logger.SugarLog.Errorf("Package RPM license %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", pkg.Name)
		ret = true
		goto gotFailure
	}
	if pkg.RpmVendor != "" && HasControlChars(pkg.RpmVendor) {
		logger.SugarLog.Errorf("Package RPM vendor %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", pkg.Name)
		ret = true
		goto gotFailure
	}
	if pkg.RpmGroup != "" && HasControlChars(pkg.RpmGroup) {
		logger.SugarLog.Errorf("Package RPM group %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", pkg.Name)
		ret = true
		goto gotFailure
	}
	if pkg.RpmBuildHost != "" && HasControlChars(pkg.RpmBuildHost) {
		logger.SugarLog.Errorf("Package RPM buildhost %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", pkg.Name)
		ret = true
		goto gotFailure
	}
	if pkg.RpmSourceRpm != "" && HasControlChars(pkg.RpmSourceRpm) {
		logger.SugarLog.Errorf("Package RPM sourcerpm %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", pkg.Name)
		ret = true
		goto gotFailure
	}
	if pkg.RpmPackager != "" && HasControlChars(pkg.RpmPackager) {
		logger.SugarLog.Errorf("Package RPM packager %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", pkg.Name)
		ret = true
		goto gotFailure
	}
	if pkg.LocationHref != "" && HasControlChars(pkg.LocationHref) {
		logger.SugarLog.Errorf("Package location href %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", pkg.Name)
		ret = true
		goto gotFailure
	}
	if pkg.LocationBase != "" && HasControlChars(pkg.LocationBase) {
		logger.SugarLog.Errorf("Package location base %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", pkg.Name)
		ret = true
		goto gotFailure
	}

	if DependencyListContainsForbiddenControlChars(pkg.Requires) {
		logger.SugarLog.Errorf("One or more dependencies in 'requires' contain forbidden control chars (ASCII values <32 except 9, 10 and 13).\n")
		ret = true
		goto gotFailure
	}
	if DependencyListContainsForbiddenControlChars(pkg.Provides) {
		logger.SugarLog.Errorf("One or more dependencies in 'provides' contain forbidden control chars (ASCII values <32 except 9, 10 and 13).\n")
		ret = true
		goto gotFailure
	}
	if DependencyListContainsForbiddenControlChars(pkg.Conflicts) {
		logger.SugarLog.Errorf("One or more dependencies in 'conflicts' contain forbidden control chars (ASCII values <32 except 9, 10 and 13).\n")
		ret = true
		goto gotFailure
	}
	if DependencyListContainsForbiddenControlChars(pkg.Obsoletes) {
		logger.SugarLog.Errorf("One or more dependencies in 'obsoletes' contain forbidden control chars (ASCII values <32 except 9, 10 and 13).\n")
		ret = true
		goto gotFailure
	}
	if DependencyListContainsForbiddenControlChars(pkg.Suggests) {
		logger.SugarLog.Errorf("One or more dependencies in 'suggests' contain forbidden control chars (ASCII values <32 except 9, 10 and 13).\n")
		ret = true
		goto gotFailure
	}
	if DependencyListContainsForbiddenControlChars(pkg.Enhances) {
		logger.SugarLog.Errorf("One or more dependencies in 'enhances' contain forbidden control chars (ASCII values <32 except 9, 10 and 13).\n")
		ret = true
		goto gotFailure
	}
	if DependencyListContainsForbiddenControlChars(pkg.Recommends) {
		logger.SugarLog.Errorf("One or more dependencies in 'recommends' contain forbidden control chars (ASCII values <32 except 9, 10 and 13).\n")
		ret = true
		goto gotFailure
	}
	if DependencyListContainsForbiddenControlChars(pkg.Supplements) {
		logger.SugarLog.Errorf("One or more dependencies in 'supplements' contain forbidden control chars (ASCII values <32 except 9, 10 and 13).\n")
		ret = true
		goto gotFailure
	}

	for _, f := range pkg.Files {
		if f.FullPath != "" && HasControlChars(f.FullPath) {
			logger.SugarLog.Errorf("File path %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", f.FullPath)
			ret = true
			goto gotFailure
		}
	}

	for _, ch := range pkg.Changelogs {
		if ch.Author != "" && HasControlChars(ch.Author) {
			logger.SugarLog.Errorf("Changelog author %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", ch.Author)
			ret = true
			goto gotFailure
		}
		if ch.Changelog != "" && HasControlChars(ch.Changelog) {
			logger.SugarLog.Errorf("Changelog entry %s contains forbidden control chars (ASCII values <32 except 9, 10 and 13).\n", ch.Changelog)
			ret = true
			goto gotFailure
		}
	}

gotFailure:
	return ret
}

func GetPrimaryPackage(pkg *model.Package, taskID int64) *model.PrimaryPackage {
	return &model.PrimaryPackage{
		ID:   taskID,
		Type: "rpm",
		Name: pkg.Name,
		Arch: pkg.Arch,
		Version: model.Version{
			Epoch: pkg.Epoch,
			Ver:   pkg.Version,
			Rel:   pkg.Release,
		},
		Checksum: model.Checksum{
			Type:  pkg.ChecksumType,
			PkgID: "YES",
			Value: pkg.PkgId,
		},
		Summary:     pkg.Summary,
		Description: pkg.Description,
		Packager:    pkg.RpmPackager,
		URL:         pkg.Url,
		Time: model.Time{
			File:  fmt.Sprintf("%d", pkg.TimeFile),
			Build: fmt.Sprintf("%d", pkg.TimeBuild),
		},
		Size: model.Size{
			Package:   fmt.Sprintf("%d", pkg.SizePackage),
			Installed: fmt.Sprintf("%d", pkg.SizeInstalled),
			Archive:   fmt.Sprintf("%d", pkg.SizeArchive),
		},
		Location: model.Location{
			Href:    pkg.LocationHref,
			XMLBase: PrependProtocol(pkg.LocationBase),
		},
		Format: model.Format{
			License:   pkg.RpmLicense,
			Vendor:    pkg.RpmVendor,
			Group:     pkg.RpmGroup,
			BuildHost: pkg.RpmBuildHost,
			SourceRPM: pkg.RpmSourceRpm,
			HeaderRange: model.HeaderRange{
				Start: fmt.Sprintf("%d", pkg.RpmHeaderStart),
				End:   fmt.Sprintf("%d", pkg.RpmHeaderEnd),
			},
			Provides:    XMLDumpPrimaryDumpPCOR(pkg.Provides, constant.DEP_PROVIDES),
			Conflicts:   XMLDumpPrimaryDumpPCOR(pkg.Conflicts, constant.DEP_CONFLICTS),
			Obsoletes:   XMLDumpPrimaryDumpPCOR(pkg.Obsoletes, constant.DEP_OBSOLETES),
			Requires:    XMLDumpPrimaryDumpPCOR(pkg.Requires, constant.DEP_REQUIRES),
			Suggests:    XMLDumpPrimaryDumpPCOR(pkg.Suggests, constant.DEP_SUGGESTS),
			Enhances:    XMLDumpPrimaryDumpPCOR(pkg.Enhances, constant.DEP_ENHANCES),
			Recommends:  XMLDumpPrimaryDumpPCOR(pkg.Recommends, constant.DEP_RECOMMENDS),
			Supplements: XMLDumpPrimaryDumpPCOR(pkg.Supplements, constant.DEP_SUPPLEMENTS),
			Files:       XMLDumpFiles(pkg.Files, true, false),
		},
	}
}

func GetFilelistsPackage(pkg *model.Package, isFilelistsExt bool, taskID int64) *model.FilelistsPackage {
	filelistsPkg := &model.FilelistsPackage{
		ID:    taskID,
		PkgID: pkg.PkgId,
		Name:  pkg.Name,
		Arch:  pkg.Arch,
		Version: model.Version{
			Epoch: pkg.Epoch,
			Ver:   pkg.Version,
			Rel:   pkg.Release,
		},
		File: XMLDumpFiles(pkg.Files, false, isFilelistsExt),
	}
	if isFilelistsExt {
		filelistsPkg.Checksum = &model.FilelistsChecksum{
			Type: pkg.ChecksumType,
		}
	}
	return filelistsPkg
}

func GetOtherPackage(pkg *model.Package, taskID int64) *model.OtherPackage {
	otherPkg := &model.OtherPackage{
		ID:    taskID,
		PkgID: pkg.PkgId,
		Name:  pkg.Name,
		Arch:  pkg.Arch,
		Version: model.Version{
			Epoch: pkg.Epoch,
			Ver:   pkg.Version,
			Rel:   pkg.Release,
		},
	}
	var changeLogList []*model.Changelog
	for _, cLog := range pkg.Changelogs {
		changeLogList = append(changeLogList, &model.Changelog{
			Content: cLog.Changelog,
			Author:  cLog.Author,
			Date:    fmt.Sprintf("%d", cLog.Date),
		})
	}
	if changeLogList != nil {
		otherPkg.Changelog = changeLogList
	}
	return otherPkg
}

func XMLDumpFiles(files []model.PackageFile, isPrimary bool, isFilelistsExt bool) []*model.File {
	var xmlFiles []*model.File
	for _, f := range files {
		if f.FullPath == "" {
			continue
		}
		if isPrimary && !CrIsPrimary(f.FullPath) {
			continue
		}
		file := &model.File{
			Value: f.FullPath,
		}
		if f.Type != "" && f.Type != "file" {
			file.Type = f.Type
		}
		if isFilelistsExt && f.Digest != "" {
			file.Hash = f.Digest
		}
		xmlFiles = append(xmlFiles, file)
	}
	return xmlFiles
}

func XMLDumpPrimaryDumpPCOR(dependencies []model.Dependency, depType constant.DepType) *model.DepEntryList {
	var depEntryList *model.DepEntryList
	if len(dependencies) > 0 {
		depEntryList = &model.DepEntryList{}
		for _, dep := range dependencies {
			if dep.Name == "" {
				continue
			}
			entry := model.DepEntry{
				Name: dep.Name,
			}
			if dep.Flags != "" {
				entry.Flags = dep.Flags
				if dep.Epoch != "" {
					entry.Epoch = dep.Epoch
				}
				if dep.Version != "" {
					entry.Ver = dep.Version
				}
				if dep.Release != "" {
					entry.Rel = dep.Release
				}
			}
			if depType == constant.DEP_REQUIRES && dep.Pre {
				entry.Pre = "1"
			}
			depEntryList.Entries = append(depEntryList.Entries, entry)
		}
	}
	return depEntryList
}

// PrependProtocol checks if the given URL starts with a forward slash and,
// if so, prepends "file://" to it. Otherwise, it returns the URL as is.
func PrependProtocol(url string) string {
	if strings.HasPrefix(url, "/") {
		return "file://" + url
	}
	return url
}

func CompressFileToZstd(inputPath, outputPath string) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// createrepo_c is using default 10, but go library only support 1/3/7/11, use 7 instead
	encoder, err := zstd.NewWriter(outputFile, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(7)))
	if err != nil {
		return err
	}
	defer encoder.Close()

	_, err = io.Copy(encoder, inputFile)
	if err != nil {
		return err
	}

	return nil
}

func DumpXML(obj any) ([]byte, error) {
	xmlData, err := xml.MarshalIndent(obj, "", "  ")
	if err != nil {
		return nil, err
	}
	return []byte(xml.Header + string(xmlData)), nil
}

func ChecksumBytes(content []byte, checkSumType constant.ChecksumType) (string, error) {
	var hasher hash.Hash
	switch checkSumType {
	case constant.ChecksumSHA256:
		hasher = sha256.New()
	case constant.ChecksumUnknown:
	default:
		return "", fmt.Errorf("unknown checksum type")
	}
	hasher.Write(content)
	sha256Bytes := hasher.Sum(nil)
	return hex.EncodeToString(sha256Bytes), nil
}

func CompressXMLToZstd(xmlData []byte, outputPath string) error {
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// createrepo_c is using default 10, but go library only support 1/3/7/11, use 7 instead
	encoder, err := zstd.NewWriter(outputFile, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(7)))
	if err != nil {
		return err
	}
	defer encoder.Close()

	_, err = encoder.Write(xmlData)
	if err != nil {
		return err
	}

	return nil
}

func WriteXML(obj any, filepath string) error {
	xmlData, err := xml.MarshalIndent(obj, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling to XML:", err)
		return nil
	}

	xmlData = []byte(xml.Header + string(xmlData))

	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("error creating XML file %s: %v", filepath, err)
	}
	defer file.Close()

	_, err = file.Write(xmlData)
	if err != nil {
		return fmt.Errorf("error writing XML data to file %s: %v", filepath, err)
	}

	return nil
}

func InitXMLStructAll() *model.XMLStructAll {
	return &model.XMLStructAll{
		PrimaryXMLData: model.PrimaryXMLData{
			Xmlns:    constant.CR_XML_COMMON_NS,
			XmlnsRPM: constant.CR_XML_RPM_NS,
		},
		FilelistsXMLData: model.FilelistsXMLData{
			Xmlns: constant.CR_XML_FILELISTS_NS,
		},
		OtherXMLData: model.OtherXMLData{
			Xmlns: constant.CR_XML_OTHER_NS,
		},
		FilelistsExtXMLData: model.FilelistsExtXMLData{
			Xmlns: constant.CR_XML_FILELISTS_EXT_NS,
		},
	}
}

func StatFile(fullPath string) (int64, int64, error) {
	statBuf, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, fmt.Errorf("file does not exist: %s", fullPath)
		}
		if e, ok := err.(*os.PathError); ok && e.Err == syscall.ENOENT {
			return 0, 0, fmt.Errorf("stat(%s) failed: %s", fullPath, e.Err)
		}
		return 0, 0, fmt.Errorf("stat(%s) failed: %v", fullPath, err)
	}
	return statBuf.ModTime().Unix(), statBuf.Size(), nil
}

func RecordTypeValue(recordType constant.RepomdType) int {
	switch recordType {
	case "primary":
		return 1
	case "filelists":
		return 2
	case "other":
		return 3
	case "primary_db":
		return 4
	case "filelists_db":
		return 5
	case "other_db":
		return 6
	case "primary_zck":
		return 7
	case "filelists_zck":
		return 8
	case "other_zck":
		return 9
	default:
		return 10
	}
}

// RecordCmp compares two crRepomdRecord pointers and returns an integer for sorting purposes.
func RecordCmp(a, b *model.RepomdRecord) int {
	aVal := RecordTypeValue(constant.RepomdType(a.Type))
	bVal := RecordTypeValue(constant.RepomdType(b.Type))

	if aVal < bVal {
		return -1
	}
	if aVal > bVal {
		return 1
	}

	// Other metadata sort by the type
	ret := strings.Compare(a.Type, b.Type)
	if ret != 0 {
		return ret
	}

	// If even the type is not sufficient, use location href
	ret = strings.Compare(a.Location.Href, b.Location.Href)
	if ret != 0 {
		return ret
	}

	// If even the location href is not sufficient, use the location base
	return strings.Compare(a.Location.XMLBase, b.Location.XMLBase)
}

func ReverseArray[T any](slice []T) {
	for i, j := 0, len(slice)-1; i < j; i, j = i+1, j-1 {
		slice[i], slice[j] = slice[j], slice[i]
	}
}
