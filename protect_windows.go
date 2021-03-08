// +build windows

package nativeprotect

import (
	"github.com/billgraziano/dpapi"
)

// protect
func ProtectNative(bytes []byte) error {

	return dpapi.EncryptBytesMachineLocal(bytes)
}

// unprotectKey
func UnprotectNative(cipherBytes []byte) ([]byte, error) {

	return dpapi.DecryptBytes(cipherBytes)
}
