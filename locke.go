package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	lockeDotFileName = ".locke"
	filePermissions  = 0660
	lockeFileSuffix  = "lockefile"
	lockeSignature   = "AHOY8BEP3UBZKJG2EYHA7ZTP8DE7S3ZLB8CBMHC9AJRP3M0KAPCSNU6XHELGY9QX"
)

var (
	pwd          = must(os.Getwd())
	homedir      = must(os.UserHomeDir())
	lockeDotFile = filepath.Join(homedir, lockeDotFileName)
)

var (
	initLockeDotFile = flag.Bool("init", false, "create ~/.locke configuration file")
	lockFilepath     = flag.String("lock", "", "lock a specified file")
	unlockFilepath   = flag.String("unlock", "", "unlock a specified file")
	newKeyName       = flag.String("new-key", "", "create a new key (input value is key name)")
	targetKeyName    = flag.String("key", "", "key to use for locking/unlocking")
	openFlag         = flag.Bool("open", false, "unlock all files in this directory recursively")
)

func main() {
	flag.Parse()

	if *initLockeDotFile {
		lockeCfg := &LockeConfiguration{
			Keychain: []*Key{{
				KeyName:  "dev",
				KeyValue: newEncryptionKey(),
			}},
		}
		writeFile(lockeDotFile, toJson(lockeCfg))
		fmt.Printf("created a locke config file at %s", lockeDotFile)
		os.Exit(0)
	}

	_, err := os.Stat(lockeDotFile)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("run locke --init to create a config file at ~/.locke")
		os.Exit(1)
	}
	check(err)

	cfgFileBytes := must(os.ReadFile(lockeDotFile))
	cfg := fromJson[*LockeConfiguration](cfgFileBytes)

	switch true {

	case *lockFilepath != "":
		if *targetKeyName == "" {
			fmt.Println("must supply key to lock file with")
			os.Exit(1)
		}
		key := cfg.getKey(*targetKeyName)
		file := filepath.Join(pwd, *lockFilepath)
		lockFile(file, key)
		cfg.UnlockedFiles = filter(cfg.UnlockedFiles, func(uf *UnlockedFile) bool { return uf.Path == file })
		WriteJsonFile(lockeDotFile, cfg)

	case *newKeyName != "":
		cfg.Keychain = append(cfg.Keychain, &Key{
			KeyName:  *newKeyName,
			KeyValue: newEncryptionKey(),
		})
		WriteJsonFile(lockeDotFile, cfg)
		fmt.Printf("created key %s", *newKeyName)

	case *unlockFilepath != "":
		unlockSingleFile(cfg, *unlockFilepath)

	case *openFlag:
		openCommand(cfg)

	case *targetKeyName == "" && len(os.Args[1:]) > 0:
		for _, arg := range os.Args[1:] {
			unlockSingleFile(cfg, arg)
		}

	case len(os.Args[1:]) == 0:
		for _, uf := range cfg.UnlockedFiles {
			key := cfg.getKey(uf.KeyName)
			lockFile(uf.Path, key)
		}
		cfg.UnlockedFiles = nil
		WriteJsonFile(lockeDotFile, cfg)
		fmt.Println("all files locked")

	default:
		flag.PrintDefaults()
		fmt.Println("all program config stored in " + lockeDotFile)
		os.Exit(1)
	}
}

func unlockSingleFile(cfg *LockeConfiguration, relativeFilePath string) {
	file := filepath.Join(pwd, relativeFilePath)
	bytes := must(os.ReadFile(file))
	if !containsLockeSignature(bytes) {
		fmt.Printf("not a locked file: %s\n", file)
		os.Exit(1)
	}
	lf := fromJson[*LockedFile](bytes)
	key := cfg.getKey(lf.KeyName)
	uf := unlockFile(file, lf, key)
	cfg.UnlockedFiles = append(cfg.UnlockedFiles, uf)
	WriteJsonFile(lockeDotFile, cfg)
}

func openCommand(cfg *LockeConfiguration) {
	check(filepath.WalkDir(pwd, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !de.IsDir() && strings.Contains(de.Name(), lockeFileSuffix) {
			bytes := must(os.ReadFile(path))
			if !containsLockeSignature(bytes) {
				return nil
			}
			lf := fromJson[*LockedFile](bytes)
			for _, key := range cfg.Keychain {
				if lf.KeyName == key.KeyName {
					uf := unlockFile(path, lf, key)
					cfg.addUnlockedFile(uf)
				}
			}
		}
		return nil
	}))
	fmt.Printf("opened all files in %s\n", pwd)
}

func handlePanic(path, cmd string) {
	if r := recover(); r != nil {
		fmt.Printf("failed to %s file: %s\n", cmd, path)
		fmt.Println(r)
		os.Exit(1)
	}
}

func containsLockeSignature(bytes []byte) bool {
	return strings.Contains(string(bytes), lockeSignature)
}

func unlockFile(path string, lockedFile *LockedFile, key *Key) *UnlockedFile {
	if key.KeyName != lockedFile.KeyName {
		panic(fmt.Sprintf("wrong key \"%s\" used in attempt to unlock file: %s", key.KeyName, path))
	}
	plaintext := decrypt(lockedFile.Ciphertext, []byte(key.KeyValue))
	writeFile(path, plaintext)
	fmt.Printf("unlocked file: \"%s\" with key: \"%s\"\n", path, key.KeyName)

	return &UnlockedFile{
		Path:    path,
		KeyName: key.KeyName,
	}
}

func lockFile(path string, key *Key) {
	defer handlePanic(path, "lock")
	bytes := must(os.ReadFile(path))
	if containsLockeSignature(bytes) {
		fmt.Printf("file %s already locked\n", path)
		return
	}
	ef := &LockedFile{
		LockeSignature: lockeSignature,
		KeyName:        key.KeyName,
		LockedAt:       time.Now().Truncate(time.Millisecond).String(),
		Ciphertext:     encrypt(bytes, []byte(key.KeyValue)),
	}
	writeFile(path, toJson(ef))
	fmt.Printf("locked %s\n", path)
}