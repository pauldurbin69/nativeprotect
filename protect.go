package nativeprotect

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
