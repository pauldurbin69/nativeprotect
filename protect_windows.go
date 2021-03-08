// +build windows

package protectecdh

import (
	"crypto/ecdsa"
	"github.com/pauldurbin69/ecdh"
	"io/ioutil"
	"os"

	"github.com/billgraziano/dpapi"
)

// func protectKey(privateKey *ecdsa.PrivateKey) error {

func protectKey(privateKey *ecdsa.PrivateKey) error {

	key, err := getKey()
	home, err := os.UserHomeDir()

	bytes, err := ecdh.EncodeEcPrivateKey(privateKey, key)

	cipherBytes, err := dpapi.EncryptBytesMachineLocal(bytes)

	err = ioutil.WriteFile(home+"/"+keyFileName, cipherBytes, 0600)

	return err
}

// unprotectKey
func unprotectKey() (*ecdsa.PrivateKey, error) {

	home, err := os.UserHomeDir()
	
	cipherBytes, err := ioutil.ReadFile(home + "/" + keyFileName)

	encPriv, err := dpapi.DecryptBytes(cipherBytes)

	key, err := getKey()

	privateKey, err := ecdh.DecodeEcPrivateKey(encPriv, key)

	return privateKey, err
}
