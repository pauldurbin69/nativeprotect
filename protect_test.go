package nativeprotect

import "testing"

func TestProtect(t *testing.T) {

	wibble := "wibble"
	got, err := Protect([]byte(wibble))
	if err != nil {
		t.Error(err)
	}
	if got == nil {
		t.Error("Got empty machine id")
	}

	plainTextBack, err := Unprotect(got)

	if string(plainTextBack) != wibble {
		t.Error("incorrect decrypted value")
	}
}

func TestSaveSecret(t *testing.T) {

	err := SaveSecret("wibble-file", []byte("wibble"))

	if err != nil {
		t.Error(err)
	}
}

func TestLoadSecret(t *testing.T) {

	wibble := "wibble"
	err := SaveSecret("wibble-file", []byte(wibble))

	cipherBytes, err := LoadSecret("wibble-file")

	if err != nil {
		t.Error(err)
	}

	plainTextBack, err := Unprotect(cipherBytes)

	if string(plainTextBack) != wibble {
		t.Error("incorrect decrypted value")
	}
}
