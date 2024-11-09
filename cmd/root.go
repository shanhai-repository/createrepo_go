package cmd

import (
	"errors"
	"fmt"
	"github.com/shanhai-repository/createrepo_go/pkg/generator"
	"github.com/shanhai-repository/createrepo_go/pkg/logger"
	"github.com/shanhai-repository/createrepo_go/pkg/util"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
)

type CreateRepoError struct {
	error
}

func (e CreateRepoError) Error() string {
	return fmt.Sprintf("CreateRepoError: %v", e.error)
}

var (
	Version           string
	VersionFlag       bool
	Verbose           bool
	IgnoreLock        bool
	FilelistsExt      bool
	UniqueMdFilenames bool
	OutputDir         string
	rootCmd           = &cobra.Command{
		Use:   "createrepo_go [flags] <directory_to_index>",
		Short: "createrepo_go [flags] <directory_to_index>",
		Long:  `Program that creates a repomd (xml-based rpm metadata) repository from a set of rpms.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Initialize(Verbose)
			if VersionFlag {
				fmt.Println("Version: ", Version)
				return nil
			}
			if len(args) != 1 {
				return fmt.Errorf("must specify exactly one directory to index")
			}
			inDir := args[0]
			if !util.IsDir(util.NormalizeDirPath(inDir)) {
				return fmt.Errorf("directory %s does not exist", inDir)
			}

			if err := generator.CreateRepo(inDir); err != nil {
				return CreateRepoError{err}
			}
			return nil
		},
	}
)

func Execute() {
	rootCmd.SilenceUsage = true
	if err := rootCmd.Execute(); err != nil {
		var crErr CreateRepoError
		if errors.As(err, &crErr) {
			os.Exit(2)
		} else {
			_ = rootCmd.Usage()
			os.Exit(1)
		}
	}
}

func init() {
	rootCmd.Flags().BoolVarP(&VersionFlag, "version", "V", false, "Show program's version number and exit.")
	rootCmd.Flags().BoolVarP(&Verbose, "verbose", "v", false, "Run verbosely.")
	rootCmd.Flags().BoolVarP(&IgnoreLock, "ignore-lock", "", false, "Run verbosely.")
	viper.BindPFlag("ignore-lock", rootCmd.Flags().Lookup("ignore-lock"))
	rootCmd.Flags().BoolVarP(&FilelistsExt, "filelists-ext", "", false, "Create filelists-ext metadata with file hashes.")
	viper.BindPFlag("filelists-ext", rootCmd.Flags().Lookup("filelists-ext"))
	rootCmd.Flags().BoolVarP(&UniqueMdFilenames, "unique-md-filenames", "", true, "Include the file's checksum in the metadata filename, helps HTTP caching (default).")
	viper.BindPFlag("unique-md-filenames", rootCmd.Flags().Lookup("unique-md-filenames"))
	rootCmd.Flags().StringVarP(&OutputDir, "outputdir", "o", "", "Optional output directory.")
	viper.BindPFlag("outputdir", rootCmd.Flags().Lookup("outputdir"))
	rootCmd.Flags().MarkHidden("ignore-lock")
}
