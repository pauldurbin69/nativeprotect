// +build windows

package protect

import (

	"github.com/billgraziano/dpapi"
)

// protect
func protect(bytes []byte) error {

	return dpapi.EncryptBytesMachineLocal(bytes)
}

// unprotectKey
func unprotect(cipherBytes []byte) (bytes []byte, error) {

	return dpapi.DecryptBytes(cipherBytes)
}
