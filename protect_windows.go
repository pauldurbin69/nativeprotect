// +build windows

package nativeprotect

import (
	"github.com/billgraziano/dpapi"
)

// protectNative
func protectNative(bytes []byte) ([]byte, error) {

	return dpapi.EncryptBytesMachineLocal(bytes)
}

// unprotectNative
func unprotectNative(cipherBytes []byte) ([]byte, error) {

	return dpapi.DecryptBytes(cipherBytes)
}
