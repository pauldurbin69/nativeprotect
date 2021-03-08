package protectecdh

// Protect write ecdh private key to OS secured file
func Protect(bytes []byte) error {

	return protectKey(bytes)
}

// Unprotect read ecdh private key from OS secured file
func Unprotect() ([]byte, error) {

	return unprotectKey()
}
