package protect

// Protect write ecdh private key to OS secured file
func Protect(clearBytes []byte) ([]byte, error) {

	return protect(clearBytes)
}

// Unprotect read ecdh private key from OS secured file
func Unprotect(cipherBytes []byte) ([]byte, error) {

	return unprotect(cipherBytes)
}
