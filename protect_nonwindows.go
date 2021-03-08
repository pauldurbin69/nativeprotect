package protectecdh

import (
	"crypto/ecdsa"
	"encoding/hex"
	"log"
	"os"

	"github.com/pauldurbin69/ecdh"

	"github.com/denisbrodbeck/machineid"
)

const (
	appKey      = "h&ji(_8G$$hhukkwy56"
	keyFileName = ".ecdh-key"
)

// Protect
func protectKey(privateKey *ecdsa.PrivateKey) error {

	key, err := getKey()
	home, err := os.UserHomeDir()

	err = ecdh.SaveEcdhKeyToFile(privateKey, key, home+"/"+keyFileName)

	return err
}

// UnprotectKey
func unprotectKey() (*ecdsa.PrivateKey, error) {

	key, err := getKey()
	home, err := os.UserHomeDir()
	privateKey, err := ecdh.ReadEcdhKeyFromFile(key, home+"/"+keyFileName)

	return privateKey, err
}

func getKey() ([]byte, error) {

	id, err := machineid.ProtectedID(appKey)
	if err != nil {
		log.Fatal(err)
	}

	key, err := hex.DecodeString(id)

	return key, err
}
