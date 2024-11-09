# createrepo_go

A basic Go version of [createrepo_c](https://github.com/rpm-software-management/createrepo_c).

## Usage

You can use the Go binary to create RPM metadata repositories.

Currently, it supports only a few flags and is not as feature-rich as [createrepo_c](https://github.com/rpm-software-management/createrepo_c).

It is designed only for RPM metadata creation and does not yet support `modulemd`.

```
[root@localhost ~]# ./createrepo_go -h                               
Program that creates a repomd (xml-based rpm metadata) repository from a set of rpms.

Usage:
  createrepo_go [flags] <directory_to_index>

Flags:
      --filelists-ext         Create filelists-ext metadata with file hashes.
  -h, --help                  help for createrepo_go
  -o, --outputdir string      Optional output directory.
      --unique-md-filenames   Include the file's checksum in the metadata filename, helps HTTP caching (default). (default true)
  -v, --verbose               Run verbosely.
  -V, --version               Show program's version number and exit.

[root@localhost ~]# ./createrepo_go /rpm_repo/go_noarch
INFO    Directory walk started
INFO    Directory walk done - 3 packages
INFO    Temporary output repo path: /rpm_repo/go_noarch/.repodata
INFO    Pool started with 5 workers
INFO    All 3 packages succeeded

[root@localhost ~]# tree /rpm_repo/go_noarch 
/Users/xiangche/rpm_repo/go_noarch
├── aaa.noarch.rpm
├── bbb.noarch.rpm
├── repodata
│         ├── 10d062137e12fc9b3cbfa916c900908c730b79fbd834450e7dfe10ab87f4bb95-primary.xml.zst
│         ├── 70a46b242575762f7f208433af686c5760a33f7190701e36cf50b0065821f383-filelists.xml.zst
│         ├── 7250cf85b8a2aa831eaa29df8aba09b77f3b02c13de679170c05e026316288e8-other.xml.zst
│         └── repomd.xml
└── sub
    └── ccc.noarch.rpm
```

## Build

You can build yourself if you have installed Go 1.23 locally.

```
# in root folder
[root@localhost createrepo_go]# make build
```
