// +build freebsd netbsd openbsd dragonfly solaris darmin linux

package nativeprotect

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log"

	"github.com/denisbrodbeck/machineid"
)

var (
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize = errors.New("invalid blocksize")

	// ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrInvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")

	// ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")
)

const (
	appKey = "h&ji(_8G$$hhukkwy56"
)

// Protect
func protect(clearBytes []byte) ([]byte, error) {

	cryptKey, err := getKey()

	// Create the AES cipher
	block, err := aes.NewCipher(cryptKey)
	if err != nil {
		panic(err)
	}

	clearBytes, _ = pkcs7Pad(clearBytes, block.BlockSize())
	iv := randombytes(aes.BlockSize)

	cipherBytes := make([]byte, len(iv)+
		len(clearBytes))

	copy(cipherBytes[0:len(iv)], iv[:])

	bm := cipher.NewCBCEncrypter(block, iv)
	bm.CryptBlocks(cipherBytes[len(iv):], clearBytes)

	return cipherBytes, nil
}

// UnprotectKey
func unprotect(combinedBytes []byte) ([]byte, error) {

	cryptKey, err := getKey()

	// Create the AES cipher
	block, err := aes.NewCipher(cryptKey)
	if err != nil {
		panic(err)
	}

	iv := combinedBytes[0:aes.BlockSize]
	cipherBytes := combinedBytes[aes.BlockSize:]

	bm := cipher.NewCBCDecrypter(block, iv)
	bm.CryptBlocks(cipherBytes, cipherBytes)

	return pkcs7Unpad(cipherBytes, block.BlockSize())
}

func randombytes(size int) []byte {

	bytes := make([]byte, size)

	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		panic(err)
	}

	return bytes
}

// pkcs7Pad right-pads the given byte slice with 1 to n bytes, where
// n is the block size. The size of the result is x times n, where x
// is at least 1.
// https://gist.github.com/huyinghuan/7bf174017bf54efb91ece04a48589b22
func pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

// pkcs7Unpad validates and unpads data from the given bytes slice.
// The returned value will be 1 to n bytes smaller depending on the
// amount of padding, where n is the block size.
func pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	if len(b)%blocksize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, ErrInvalidPKCS7Padding
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, ErrInvalidPKCS7Padding
		}
	}
	return b[:len(b)-n], nil
}

func getKey() ([]byte, error) {

	id, err := machineid.ProtectedID(appKey)

	if err != nil {
		log.Fatal(err)
	}

	key, err := hex.DecodeString(id)

	return key, err
}
