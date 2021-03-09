package nativeprotect

import (
	"io/ioutil"
	"os"
)

// Protect some stuff
func Protect(clearBytes []byte) ([]byte, error) {
	// Return a greeting that embeds the name in amessage := fmt.Sprintf("Hi, %v. Welcome!", name) message.

	return protectNative(clearBytes)
}

// Unprotect some stuff
func Unprotect(cipherBytes []byte) ([]byte, error) {
	// Return a greeting that embeds the name in amessage := fmt.Sprintf("Hi, %v. Welcome!", name) message.

	return unprotectNative(cipherBytes)
}

// LoadSecret get encrypted data back from file in UserHomeDir()
func LoadSecret(fileName string) ([]byte, error) {

	path, err := getKeyFilePath(fileName)

	if err != nil {
		return nil, err
	}

	return ioutil.ReadFile(path)
}

// SaveSecret encrypted and save data to file in UserHomeDir() with r/w for user only
func SaveSecret(fileName string, clearBytes []byte) error {

	cipherBytes, err := protectNative(clearBytes)

	if err != nil {
		return err
	}

	path, err := getKeyFilePath(fileName)

	if err != nil {
		return err
	}

	// save to path user r/w only
	return ioutil.WriteFile(path, cipherBytes, 0600)
}

func getKeyFilePath(fileName string) (string, error) {

	home, err := os.UserHomeDir()

	if err != nil {
		return "", nil
	}

	return home + "/" + fileName, nil
}
