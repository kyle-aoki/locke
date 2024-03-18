package main

import (
	"fmt"
	"os"
)

type UnlockedFile struct {
	Path    string
	KeyName string
}

type LockeConfiguration struct {
	Keychain      []*Key
	UnlockedFiles []*UnlockedFile
}

func (lc *LockeConfiguration) addUnlockedFile(uf *UnlockedFile) {
	lc.UnlockedFiles = append(lc.UnlockedFiles, uf)
	WriteJsonFile(lockeDotFile, lc)
}

func (lc *LockeConfiguration) getKey(name string) *Key {
	for i := range lc.Keychain {
		if lc.Keychain[i].KeyName == name {
			return lc.Keychain[i]
		}
	}
	fmt.Println("key " + name + " not found in ~/.locke")
	os.Exit(1)
	return nil
}

type LockedFile struct {
	LockeSignature string
	KeyName        string
	LockedAt       string
	Ciphertext     []byte
}

type Key struct {
	KeyName  string
	KeyValue string
}
