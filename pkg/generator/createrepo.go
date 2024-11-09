package generator

import (
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/sassoftware/go-rpmutils"
	"github.com/sassoftware/go-rpmutils/cpio"
	"github.com/shanhai-repository/createrepo_go/pkg/constant"
	"github.com/shanhai-repository/createrepo_go/pkg/logger"
	"github.com/shanhai-repository/createrepo_go/pkg/model"
	"github.com/shanhai-repository/createrepo_go/pkg/util"
	"github.com/spf13/viper"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// TODO default checksum
	userData = UserData{CheckSumType: constant.DefaultChecksum}
)

type PoolTask struct {
	Id       int64  // ID of the task
	MediaId  int64  // ID of media in split mode, 0 if not in split mode
	FullPath string // Complete path - /foo/bar/packages/foo.rpm
	Filename string // Just filename - foo.rpm
	Path     string // Just path     - /foo/bar/packages
}

type UserData struct {
	RepoDirNameLen int    // Len of path to repo /foo/bar/repodata, this part /foo/bar/
	LocationBase   string // Base location url
	CheckSumType   constant.ChecksumType
	ChangeLogLimit int
	FilelistsExt   bool

	// Duplicate package error checking
	MutexNEVRATable sync.Mutex
	NEVRATable      map[string][]*model.DuplicateLocation

	AllXMLStructs *model.XMLStructAll
}

type Job struct {
	UserData *UserData
	PoolTask *PoolTask
}

func FindRPMFiles(dirPath string) ([]*PoolTask, error) {
	var rpmFiles []*PoolTask

	err := filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() && strings.HasSuffix(d.Name(), ".rpm") {
			rpmFiles = append(rpmFiles, &PoolTask{
				FullPath: path,
				Filename: d.Name(),
				Path:     filepath.Dir(path),
			})
		}
		return nil
	})

	sortPoolTasks(rpmFiles)

	for i, v := range rpmFiles {
		v.Id = int64(i)
		v.MediaId = 0 // TODO not support --split like createrepo_c
	}
	return rpmFiles, err
}

func taskCmp(a, b *PoolTask) int {
	if cmp := strings.Compare(a.Filename, b.Filename); cmp != 0 {
		return cmp
	}
	return strings.Compare(a.FullPath, b.FullPath)
}

func sortPoolTasks(packageTasks []*PoolTask) {
	sort.Slice(packageTasks, func(i, j int) bool {
		return taskCmp(packageTasks[i], packageTasks[j]) < 0
	})
}

func CreateRepo(inDir string) error {
	inDir = util.NormalizeDirPath(inDir)
	inRepo := path.Join(inDir, "repodata") // path/to/repo/repodata/
	outDir := viper.GetString("outputdir") // path/to/out_repo/
	outRepo := ""                          // path/to/out_repo/repodata/
	tmpOutDir := ""                        // usually path/to/out_repo/.repodata/
	lockDir := ""                          // path/to/out_repo/.repodata/
	if outDir != "" {
		outDirExist, err := util.PathExists(outDir)
		if err != nil {
			return fmt.Errorf("error to check if outputdir %s exists: %v", outDir, err)
		}
		if !outDirExist {
			return fmt.Errorf("specified outputdir \"%s\" doesn't exist", outDir)
		}
		outDir = util.NormalizeDirPath(outDir)
		outRepo = path.Join(outDir, "repodata")
	} else {
		outDir = inDir
		outRepo = inRepo
	}

	logger.SugarLog.Info("Directory walk started")
	poolTasks, err := FindRPMFiles(inDir)
	if err != nil {
		return fmt.Errorf("error to walk through packages in directory %s", inDir)
	}
	totalPkgNum := len(poolTasks)
	logger.SugarLog.Infof("Directory walk done - %d packages", totalPkgNum)

	lockDir, tmpOutDir, err = lockRepo(outDir, viper.GetBool("ignore-lock"))
	if err != nil {
		return fmt.Errorf("error to lock repo: %v", err)
	}
	defer exitCleanup(lockDir)
	logger.SugarLog.Infof("Temporary output repo path: %s", tmpOutDir)

	jobs := make(chan *Job, 100)
	results := make(chan *error, 100)
	var wg sync.WaitGroup

	for i := 0; i < constant.DefaultWorkers; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg)
	}
	logger.SugarLog.Infof("Pool started with %d workers", constant.DefaultWorkers)

	userData.LocationBase = ""
	userData.FilelistsExt = viper.GetBool("filelists-ext")
	userData.ChangeLogLimit = constant.DefaultChangelogLimit
	userData.RepoDirNameLen = len(inDir)
	userData.NEVRATable = make(map[string][]*model.DuplicateLocation)
	userData.AllXMLStructs = util.InitXMLStructAll()
	for _, task := range poolTasks {
		jobs <- &Job{
			PoolTask: task,
			UserData: &userData,
		}
	}
	close(jobs)

	// wait for all jobs done
	wg.Wait()
	close(results)

	xmlCompressionSuffix := constant.CompressionSuffix(constant.DefaultCompressionType)

	priXMLFilename := tmpOutDir + "/primary.xml" + xmlCompressionSuffix
	fileXMLFilename := tmpOutDir + "/filelists.xml" + xmlCompressionSuffix
	othXMLFilename := tmpOutDir + "/other.xml" + xmlCompressionSuffix
	fexXMLFilename := ""
	supportFilelistsExt := viper.GetBool("filelists-ext")
	if supportFilelistsExt {
		fexXMLFilename = tmpOutDir + "/filelists-ext.xml" + xmlCompressionSuffix
	}
	userData.AllXMLStructs.SortPackageByTaskID()
	userData.AllXMLStructs.SetPackageNum()

	primaryRepomdRecord, err := getRepomdRecord(priXMLFilename, constant.RepomdTypePrimary)
	if err != nil {
		return err
	}
	fileRepomdRecord, err := getRepomdRecord(fileXMLFilename, constant.RepomdTypeFilelists)
	if err != nil {
		return err
	}
	otherRepomdRecord, err := getRepomdRecord(othXMLFilename, constant.RepomdTypeOther)
	if err != nil {
		return err
	}
	// Use the current time if no revision was explicitly specified
	revision := strconv.FormatInt(time.Now().Unix(), 10)
	repomd := model.Repomd{
		Xmlns:    constant.CR_XML_REPOMD_NS,
		XmlnsRpm: constant.CR_XML_RPM_NS,
		Revision: revision,
		Data:     []*model.RepomdRecord{primaryRepomdRecord, fileRepomdRecord, otherRepomdRecord},
	}
	if supportFilelistsExt {
		fexRepomdRecord, err := getRepomdRecord(fexXMLFilename, constant.RepomdTypeFilelistsExt)
		if err != nil {
			return err
		}
		repomd.Data = append(repomd.Data, fexRepomdRecord)
	}

	// Sort the records using the recordCmp function
	sort.Slice(repomd.Data, func(i, j int) bool {
		return util.RecordCmp(repomd.Data[i], repomd.Data[j]) < 0
	})

	// generate repomd.xml
	repomdPath := filepath.Join(tmpOutDir, "repomd.xml")
	if err := util.WriteXML(repomd, repomdPath); err != nil {
		return fmt.Errorf("write %s failed: %v", repomdPath, err)
	}

	// old_metadata_retention
	if err = oldMetadataRetention(outRepo, tmpOutDir); err != nil {
		return fmt.Errorf("old metadata files retention failed: %v", err)
	}
	// copy repodata files to tmpRepoDir; rename repodata to repodata.old.pid.timestamp.microseconds; rename tmpRepoDir to repodata
	exist, err := util.PathExists(outRepo)
	if err != nil {
		return err
	}
	if exist {
		oldRepo := path.Join(outDir, appendPidAndDatetime("repodata.old", ""))
		err = os.Rename(outRepo, oldRepo)
		if err != nil {
			return fmt.Errorf("rename %s to %s failed: %v", outRepo, oldRepo, err)
		}
		defer exitCleanup(oldRepo)
	}
	err = os.Rename(tmpOutDir, outRepo)
	if err != nil {
		return fmt.Errorf("rename %s to %s failed: %v", tmpOutDir, outRepo, err)
	}
	failedPkgNum := len(results)
	if failedPkgNum > 0 {
		logger.SugarLog.Warnf("%d packages failed, %d packages succeeded", failedPkgNum, totalPkgNum-failedPkgNum)
		return fmt.Errorf("finished with error")
	} else {
		logger.SugarLog.Infof("All %d packages succeeded", totalPkgNum)
	}
	return nil
}

func oldMetadataRetention(oldRepo string, newRepo string) error {
	existed, err := util.PathExists(oldRepo)
	if err != nil {
		return err
	}
	if !existed {
		return nil
	}
	oldRepomdPath := path.Join(oldRepo, "repomd.xml")
	xmlFile, err := os.Open(oldRepomdPath)
	if err != nil {
		return fmt.Errorf("error opening file %s: %v", oldRepomdPath, err)
	}
	defer xmlFile.Close()

	xmlData, err := io.ReadAll(xmlFile)
	if err != nil {
		return fmt.Errorf("error reading file %s: %v", oldRepomdPath, err)
	}

	var repomdData model.Repomd
	if err := xml.Unmarshal(xmlData, &repomdData); err != nil {
		return fmt.Errorf("error unmarshaling XML to %s: %v", oldRepomdPath, err)
	}

	excludedList := []string{"repomd.xml"}
	for _, repomdRecord := range repomdData.Data {
		href := repomdRecord.Location.Href
		if href == "" {
			continue
		}
		if repomdRecord.Location.XMLBase != "" {
			continue
		}
		excludedList = append(excludedList, filepath.Base(href))
	}

	entries, err := os.ReadDir(oldRepo)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if util.Contains(excludedList, entry.Name()) {
			continue
		}
		srcPath := path.Join(oldRepo, entry.Name())
		dstPath := path.Join(newRepo, entry.Name())
		if entry.IsDir() {
			if err = util.CopyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err = util.CopyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return err
}

func getRepomdRecord(xmlCompressedFilePath string, repomdType constant.RepomdType) (repomdRec *model.RepomdRecord, err error) {
	var xmlBytes []byte
	if repomdType == constant.RepomdTypePrimary {
		xmlBytes, err = util.DumpXML(userData.AllXMLStructs.PrimaryXMLData)
	} else if repomdType == constant.RepomdTypeFilelists {
		xmlBytes, err = util.DumpXML(userData.AllXMLStructs.FilelistsXMLData)
	} else if repomdType == constant.RepomdTypeOther {
		xmlBytes, err = util.DumpXML(userData.AllXMLStructs.OtherXMLData)
	} else if repomdType == constant.RepomdTypeFilelistsExt {
		xmlBytes, err = util.DumpXML(userData.AllXMLStructs.FilelistsExtXMLData)
	} else {
		return nil, fmt.Errorf("invalid repomd type %s", repomdType)
	}
	if err != nil {
		return nil, err
	}
	xmlDataChecksum, err := util.ChecksumBytes(xmlBytes, constant.DefaultRepomdChecksum)
	if err != nil {
		return nil, err
	}
	if err = util.CompressXMLToZstd(xmlBytes, xmlCompressedFilePath); err != nil {
		return nil, err
	}
	compressedFileCheckSum, err := util.ChecksumFile(xmlCompressedFilePath, constant.DefaultRepomdChecksum)
	if err != nil {
		return nil, err
	}
	// rename xml file to checksum-xml.zst
	compressedFilename := filepath.Base(xmlCompressedFilePath)
	if viper.GetBool("unique-md-filenames") {
		baseDir := filepath.Dir(xmlCompressedFilePath)
		compressedFilename = fmt.Sprintf("%s-%s", compressedFileCheckSum, compressedFilename)
		oldXmlCompressedFilePath := xmlCompressedFilePath
		xmlCompressedFilePath = path.Join(baseDir, compressedFilename)
		err = os.Rename(oldXmlCompressedFilePath, xmlCompressedFilePath)
		if err != nil {
			return nil, fmt.Errorf("rename %s to %s failed: %v", oldXmlCompressedFilePath, xmlCompressedFilePath, err)
		}
	}
	statModTime, statSize, err := util.StatFile(xmlCompressedFilePath)
	if err != nil {
		return nil, err
	}
	repomdRec = &model.RepomdRecord{
		Type: string(repomdType),
		OpenChecksum: model.Checksum{
			Type:  constant.ChecksumName(constant.DefaultRepomdChecksum),
			Value: xmlDataChecksum,
		},
		OpenSize: int64(len(xmlBytes)),
		Checksum: model.Checksum{
			Type:  constant.ChecksumName(constant.DefaultRepomdChecksum),
			Value: compressedFileCheckSum,
		},
		Size: statSize,
		Location: model.Location{
			// TODO not support location base - xml:base in location
			Href: constant.LocationHrefPrefix + compressedFilename,
		},
		Timestamp: statModTime,
	}
	return repomdRec, nil
}

func exitCleanup(lockDir string) {
	if err := os.RemoveAll(lockDir); err != nil {
		logger.SugarLog.Errorf("cleanup lock dir %s failed: %v", lockDir, err)
	}
}

// lockRepo tries to create a lock directory for the repository.
// It returns the path to the lock directory and the temporary repodata directory,
// or an error if it fails.
func lockRepo(repoDir string, ignoreLock bool) (lockDir, tmpRepodataDir string, err error) {
	lockDir = filepath.Join(repoDir, ".repodata")

	// Try to create the lock directory
	if err := os.Mkdir(lockDir, 0775); err != nil {
		if !ignoreLock || !os.IsExist(err) {
			return "", "", fmt.Errorf("error while creating temporary repodata directory: %s: %w", lockDir, err)
		}

		fmt.Printf("Temporary repodata directory: %s already exists! (Another createrepo process is running?)\n", lockDir)

		// If ignoring the existing lock, remove it
		fmt.Println("(--ignore-lock enabled) Let's remove the old .repodata/")
		if err := os.RemoveAll(lockDir); err != nil {
			return "", "", fmt.Errorf("cannot remove %s (--ignore-lock enabled): %w", lockDir, err)
		}

		// Try to create the lock directory again after removing it
		if err := os.Mkdir(lockDir, 0775); err != nil {
			return "", "", fmt.Errorf("cannot create %s (--ignore-lock enabled): %w", lockDir, err)
		}

		// For data generation, use a different directory
		tmpRepodataDir = filepath.Join(repoDir, appendPidAndDatetime(".repodata", ""))
		if err := os.Mkdir(tmpRepodataDir, 0775); err != nil {
			return "", "", fmt.Errorf("cannot create %s (--ignore-lock enabled): %w", tmpRepodataDir, err)
		}
	} else {
		tmpRepodataDir = lockDir
	}

	return lockDir, tmpRepodataDir, nil
}

// appendPidAndDatetime Generate a string that includes the process ID, date and time stamp, and an optional suffix.
func appendPidAndDatetime(prefix string, suffix string) string {
	pid := os.Getpid()
	currentTime := time.Now()
	timestamp := currentTime.Format("20060102150405")
	microseconds := currentTime.Nanosecond() / 1000

	result := fmt.Sprintf("%s.%d.%s.%d", prefix, pid, timestamp, microseconds)
	if suffix != "" {
		result = fmt.Sprintf("%s.%s", result, suffix)
	}

	return result
}

func worker(jobs <-chan *Job, results chan<- *error, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		logger.SugarLog.Debugf("Processing file %s", job.PoolTask.FullPath)
		udata := job.UserData
		task := job.PoolTask
		locationHref := task.FullPath[udata.RepoDirNameLen:]
		locationBase := udata.LocationBase
		pkg, err := loadRpm(task.FullPath, udata.CheckSumType, locationHref, locationBase, udata.ChangeLogLimit)
		if err != nil {
			logger.SugarLog.Errorf("can not load rpm \"%s\": %v", task.FullPath, err)
			results <- &err
			return
		}
		// TODO seems useless
		// Allow checking that the same package (NEVRA) isn't present multiple times in the metadata
		// Keep a hashtable of NEVRA mapped to an array-list of location_href values
		//udata.MutexNEVRATable.Lock()
		//nevra := util.PackageNEVRA(pkg)
		//pkgLocations, exists := udata.NEVRATable[nevra]
		//if !exists {
		//	pkgLocations = make([]*model.DuplicateLocation, 0)
		//	udata.NEVRATable[nevra] = pkgLocations
		//}
		//udata.NEVRATable[nevra] = append(pkgLocations, &model.DuplicateLocation{
		//	Location: locationHref,
		//	Pkg:      pkg,
		//})
		//udata.MutexNEVRATable.Unlock()
		err = xmlDump(udata, task, pkg, udata.FilelistsExt)
		if err != nil {
			logger.SugarLog.Errorf("can not collect xml structure from \"%s\": %v", task.FullPath, err)
			results <- &err
			return
		}
	}
}

func xmlDump(udata *UserData, task *PoolTask, pkg *model.Package, isFilelistsExt bool) error {
	if util.PackageContainsForbiddenControlChars(pkg) {
		return fmt.Errorf("forbidden control chars found (ASCII values <32 except 9, 10 and 13)")
	}
	taskID := task.Id
	udata.AllXMLStructs.MutexPrimary.Lock()
	udata.AllXMLStructs.PrimaryXMLData.PackageList = append(udata.AllXMLStructs.PrimaryXMLData.PackageList, util.GetPrimaryPackage(pkg, taskID))
	udata.AllXMLStructs.MutexPrimary.Unlock()
	udata.AllXMLStructs.MutexFilelists.Lock()
	udata.AllXMLStructs.FilelistsXMLData.PackageList = append(udata.AllXMLStructs.FilelistsXMLData.PackageList, util.GetFilelistsPackage(pkg, false, taskID))
	udata.AllXMLStructs.MutexFilelists.Unlock()
	udata.AllXMLStructs.MutexOtherData.Lock()
	udata.AllXMLStructs.OtherXMLData.PackageList = append(udata.AllXMLStructs.OtherXMLData.PackageList, util.GetOtherPackage(pkg, taskID))
	udata.AllXMLStructs.MutexOtherData.Unlock()
	if isFilelistsExt {
		udata.AllXMLStructs.MutexFilelistsExt.Lock()
		udata.AllXMLStructs.FilelistsExtXMLData.PackageList = append(udata.AllXMLStructs.FilelistsExtXMLData.PackageList, util.GetFilelistsPackage(pkg, true, taskID))
		udata.AllXMLStructs.MutexFilelistsExt.Unlock()
	}
	return nil
}

func loadRpm(fullPath string, checksumType constant.ChecksumType, locationHref string, locationBase string, changeLogLimit int) (*model.Package, error) {
	pkg, err := packageFromRpmBase(fullPath, changeLogLimit)
	if err != nil {
		return nil, fmt.Errorf("can not get rpm header: %v", err)
	}
	pkg.LocationHref = locationHref
	pkg.LocationBase = locationBase

	statModTime, statSize, err := util.StatFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("can not stat file: %v", err)
	}

	// Update package struct with file stat info
	pkg.TimeFile = statModTime
	pkg.SizePackage = statSize

	pkg.PkgId, err = getChecksum(fullPath, checksumType, "")
	if err != nil {
		return nil, fmt.Errorf("error while checksum calculation: %v", err)
	}
	return pkg, nil
}

func getChecksum(filePath string, checksumType constant.ChecksumType, cacheDir string) (string, error) {
	if cacheDir != "" {
		// TODO
	}
	checksum, err := util.ChecksumFile(filePath, checksumType)
	if err != nil {
		return "", err
	}
	return checksum, nil
}

// cr_package_from_rpm_base + cr_package_from_header
func packageFromRpmBase(fullPath string, changeLogLimit int) (*model.Package, error) {
	f, err := os.Open(fullPath)
	if err != nil {
		return nil, err
	}
	rpm, err := rpmutils.ReadRpm(f)
	if err != nil {
		return nil, err
	}
	pkg := &model.Package{}
	headerRange := rpm.Header.GetRange()
	pkg.RpmHeaderStart = headerRange.Start
	pkg.RpmHeaderEnd = headerRange.End
	// Fill package structure
	pkg.Name, err = rpm.Header.GetString(rpmutils.NAME)
	if err != nil {
		return nil, err
	}
	if rpm.Header.IsSource() {
		pkg.Arch = "src"
	} else {
		pkg.Arch, err = rpm.Header.GetString(rpmutils.ARCH)
		if err != nil {
			return nil, err
		}
	}
	pkg.Version, err = rpm.Header.GetString(rpmutils.VERSION)
	if err != nil {
		return nil, err
	}
	pkg.Release, err = rpm.Header.GetString(rpmutils.RELEASE)
	if err != nil {
		return nil, err
	}
	epochNum, err := rpm.Header.GetUint64(rpmutils.EPOCH)
	if !valueExistsOrNoSuchTag(err) {
		return nil, err
	}
	pkg.Epoch = strconv.FormatUint(epochNum, 10)

	pkg.Summary, err = rpm.Header.GetString(rpmutils.SUMMARY)
	if err != nil {
		return nil, err
	}
	pkg.Description, err = rpm.Header.GetString(rpmutils.DESCRIPTION)
	if err != nil {
		return nil, err
	}
	pkg.Url, err = rpm.Header.GetString(rpmutils.URL)
	if !valueExistsOrNoSuchTag(err) {
		return nil, err
	}
	timeBuild, err := rpm.Header.GetUint64(rpmutils.BUILDTIME)
	if !valueExistsOrNoSuchTag(err) {
		return nil, err
	}
	pkg.TimeBuild = int64(timeBuild)

	pkg.RpmLicense, err = rpm.Header.GetString(rpmutils.LICENSE)
	if err != nil {
		return nil, err
	}
	pkg.RpmVendor, err = rpm.Header.GetString(rpmutils.VENDOR)
	if !valueExistsOrNoSuchTag(err) {
		return nil, err
	}
	pkg.RpmGroup, err = rpm.Header.GetString(rpmutils.GROUP)
	if err != nil {
		return nil, err
	}
	pkg.RpmBuildHost, err = rpm.Header.GetString(rpmutils.BUILDHOST)
	if !valueExistsOrNoSuchTag(err) {
		return nil, err
	}
	pkg.RpmSourceRpm, err = rpm.Header.GetString(rpmutils.SOURCERPM)
	if !valueExistsOrNoSuchTag(err) {
		return nil, err
	}
	pkg.RpmPackager, err = rpm.Header.GetString(rpmutils.PACKAGER)
	if !valueExistsOrNoSuchTag(err) {
		return nil, err
	}
	sizeInstalled, err := rpm.Header.InstalledSize()
	if err != nil {
		return nil, err
	}
	pkg.SizeInstalled = sizeInstalled

	fda, err := rpm.Header.GetUint64(rpmutils.FILEDIGESTALGO)
	if err != nil {
		return nil, err
	}
	pkg.ChecksumType = rpmutils.GetFileAlgoName(int(fda))

	sizeArchive, err := rpm.Header.PayloadSize()
	if !valueExistsOrNoSuchTag(err) {
		return nil, err
	}
	pkg.SizeArchive = sizeArchive

	// Fill files
	fileInfoArray, err := rpm.Header.GetFiles()
	if err != nil {
		return nil, err
	}
	filenamesHashtable := make(map[string]string)
	for _, fileInfo := range fileInfoArray {
		pf := model.PackageFile{
			FullPath: fileInfo.Name(),
			Digest:   fileInfo.Digest(),
		}
		if fileInfo.Mode()&^07777 == cpio.S_ISDIR {
			// Directory
			pf.Type = "dir"
		} else if fileInfo.Flags()&rpmutils.RPMFILE_GHOST != 0 {
			// Ghost
			pf.Type = "ghost"
		} else {
			// Regular file
			pf.Type = ""
		}
		filenamesHashtable[fileInfo.Name()] = fileInfo.Name()
		pkg.Files = append(pkg.Files, pf)
	}

	// PCOR (provides, conflicts, obsoletes, requires)

	// Hashtable with filenames from provided
	providedHashtable := make(map[string]string)
	// Hashtable with already processed files from requires
	apHashtable := make(map[string]model.ApValueStruct)
	for depType := constant.DEP_PROVIDES; constant.DepItems[depType].Type != constant.DEP_SENTINEL; depType++ {
		// Because we have to select only libc.so with the highest version
		// e.g. libc.so.6(GLIBC_2.4)
		var libcRequireHighest *model.Dependency
		nameTag := constant.DepItems[depType].NameTag
		flagsTag := constant.DepItems[depType].FlagsTag
		versionTag := constant.DepItems[depType].VersionTag
		if !rpm.Header.HasTag(nameTag) || !rpm.Header.HasTag(flagsTag) || !rpm.Header.HasTag(versionTag) {
			continue
		}
		filenames, err := rpm.Header.GetStrings(nameTag)
		if err != nil {
			return nil, err
		}
		fileFlags, err := rpm.Header.GetUint64s(flagsTag)
		if err != nil {
			return nil, err
		}
		fileVersions, err := rpm.Header.GetStrings(versionTag)
		if err != nil {
			return nil, err
		}
		filenameSize := len(filenames)
		fileFlagsSize := len(fileFlags)
		fileVersionSize := len(fileVersions)
		for i := 0; i < fileFlagsSize && i < filenameSize && i < fileVersionSize; i++ {
			pre := false
			filename := filenames[i]
			numFlags := fileFlags[i]
			flagStr := util.CrFlagToStr(numFlags)
			fullVersion := fileVersions[i]
			depnfv := filename + flagStr + fullVersion

			if depType == constant.DEP_REQUIRES {
				// Skip requires which start with "rpmlib("
				if strings.HasPrefix(filename, "rpmlib(") {
					continue
				}

				// Skip package primary files
				if strings.HasPrefix(filename, "/") && filenamesHashtable[filename] != "" {
					if util.CrIsPrimary(filename) {
						continue
					}
				}

				// Skip files which are provided
				if _, ok := providedHashtable[depnfv]; ok {
					continue
				}

				// Calculate pre value
				if numFlags&(rpmutils.RPMSENSE_PREREQ|
					rpmutils.RPMSENSE_SCRIPT_PRE|
					rpmutils.RPMSENSE_POSTTRANS|
					rpmutils.RPMSENSE_PRETRANS|
					rpmutils.RPMSENSE_SCRIPT_POST) != 0 {
					pre = true
				}

				// Skip duplicate files
				if apValue, ok := apHashtable[filename]; ok {
					if apValue.Flags == flagStr && apValue.Version == fullVersion && apValue.Pre == pre {
						continue
					}
				}
			}

			crEVR := util.StrToEVR(fullVersion)
			if fullVersion != "" && crEVR.Epoch == "" {
				logger.SugarLog.Warnf("Bad epoch in version string [%s] for dependency [%s] in package [%s], skipping this dependency", fullVersion, filename, util.PackageNEVRA(pkg))
				continue
			}

			dependency := model.Dependency{
				Name:    filename,
				Flags:   flagStr,
				Epoch:   crEVR.Epoch,
				Version: crEVR.Version,
				Release: crEVR.Release,
			}

			switch depType {
			case constant.DEP_PROVIDES:
				providedHashtable[depnfv] = ""
				pkg.Provides = append(pkg.Provides, dependency)
				break
			case constant.DEP_CONFLICTS:
				pkg.Conflicts = append(pkg.Conflicts, dependency)
				break
			case constant.DEP_OBSOLETES:
				pkg.Obsoletes = append(pkg.Obsoletes, dependency)
				break
			case constant.DEP_REQUIRES:
				// ENABLE_LEGACY_WEAKDEPS
				if numFlags&constant.RPMSENSE_MISSINGOK != 0 {
					pkg.Recommends = append(pkg.Recommends, dependency)
					break
				}
				dependency.Pre = pre

				// XXX: libc.so filtering ////////////////////////////
				if strings.HasPrefix(dependency.Name, "libc.so.6") {
					if libcRequireHighest == nil {
						libcRequireHighest = &dependency
					} else if util.CrCompareDependencyRegex(libcRequireHighest.Name, dependency.Name) == -1 {
						libcRequireHighest = &dependency
					}
					break
				}
				// XXX: libc.so filtering - END ///////////////////////

				pkg.Requires = append(pkg.Requires, dependency)

				// Add file into ap_hashtable
				apHashtable[dependency.Name] = model.ApValueStruct{
					Flags:   flagStr,
					Version: fullVersion,
					Pre:     dependency.Pre,
				}
				break
			case constant.DEP_SUGGESTS:
				pkg.Suggests = append(pkg.Suggests, dependency)
				break
			case constant.DEP_ENHANCES:
				pkg.Enhances = append(pkg.Enhances, dependency)
				break
			case constant.DEP_RECOMMENDS:
				pkg.Recommends = append(pkg.Recommends, dependency)
				break
			case constant.DEP_SUPPLEMENTS:
				pkg.Supplements = append(pkg.Supplements, dependency)
				break
			// ENABLE_LEGACY_WEAKDEPS
			case constant.DEP_OLDSUGGESTS:
				if numFlags&constant.RPMSENSE_STRONG != 0 {
					pkg.Recommends = append(pkg.Recommends, dependency)
				} else {
					pkg.Suggests = append(pkg.Suggests, dependency)
				}
				break
			case constant.DEP_OLDENHANCES:
				if numFlags&constant.RPMSENSE_STRONG != 0 {
					pkg.Supplements = append(pkg.Supplements, dependency)
				} else {
					pkg.Enhances = append(pkg.Enhances, dependency)
				}
				break
			default:
				logger.SugarLog.Warnf("Unknown dependency type for dependency: \"%s\" with version: \"%s\"",
					dependency.Name, dependency.Version)
			}
		}

		// XXX: libc.so filtering ////////////////////////////////
		if depType == constant.DEP_REQUIRES && libcRequireHighest != nil {
			pkg.Requires = append(pkg.Requires, *libcRequireHighest)
		}
		// XXX: libc.so filtering - END ////////////////////////////////
	}

	// Changelogs
	changeLogTimes, err := rpm.Header.GetUint64s(rpmutils.CHANGELOGTIME)
	if !valueExistsOrNoSuchTag(err) {
		return nil, err
	}
	changeLogNames, err := rpm.Header.GetStrings(rpmutils.CHANGELOGNAME)
	if !valueExistsOrNoSuchTag(err) {
		return nil, err
	}
	changeLogTexts, err := rpm.Header.GetStrings(rpmutils.CHANGELOGTEXT)
	if !valueExistsOrNoSuchTag(err) {
		return nil, err
	}
	logTimesSize := len(changeLogTimes)
	logNamesSize := len(changeLogNames)
	logTextsSize := len(changeLogTexts)
	var lastTime int64
	for i := 0; i < logTimesSize && i < logNamesSize && i < logTextsSize && changeLogLimit > 0; i++ {
		time := int64(changeLogTimes[i])
		changelog := model.ChangelogEntry{
			Author:    strings.TrimSpace(changeLogNames[i]),
			Date:      time,
			Changelog: changeLogTexts[i],
		}
		pkg.Changelogs = append(pkg.Changelogs, changelog)
		changeLogLimit--

		// TODO if resolve time conflict is in need ?
		if lastTime == time {
			tmpTime := time
			// Iterate over the changelogs to resolve conflicts
			for j := len(pkg.Changelogs) - 2; j >= 0 && pkg.Changelogs[i].Date == tmpTime; j-- {
				pkg.Changelogs[i].Date--
				tmpTime--
			}
		} else {
			lastTime = time
		}
	}
	util.ReverseArray(pkg.Changelogs)
	// TODO Keys and hdrid (data used for caching when the --cachedir is specified)

	return pkg, nil
}

func valueExistsOrNoSuchTag(err error) bool {
	var targetErr rpmutils.NoSuchTagError
	return err == nil || errors.As(err, &targetErr)
}
