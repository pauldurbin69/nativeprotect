package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	"github.com/pauldurbin69/nativeprotect"
)

func main() {

	var hexin, b64in, str string
	flag.StringVar(&hexin, "hex", "", "hex string to decrypt")
	flag.StringVar(&b64in, "base64", "", "base64 string to decrypt")
	flag.StringVar(&str, "encrypt", "", "string to encrypt")
	flag.Parse()

	if hexin == "" && str == "" && b64in == "" {
		fmt.Println("usage: go run .\\cmd\\dpapi\\main.go -base64 KAYORvJh -hex 01020304 -encrypt test")
		flag.Usage()
		return
	}

	if str != "" {
		encrypted, err := nativeprotect.Protect([]byte(str))
		if err != nil {
			log.Fatal(err)
		}
		hexout := hex.EncodeToString(encrypted)
		fmt.Printf("'%s' => (hex) 0x%s\n\n", str, hexout)
		b64 := base64.StdEncoding.EncodeToString(encrypted)
		fmt.Printf("'%s' => (base64) %s\n\n", str, b64)
	}

	if b64in != "" {

		bb, err := base64.StdEncoding.DecodeString(b64in)
		if err != nil {
			log.Fatal(err)
		}

		decrypted, err := nativeprotect.Unprotect(bb)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("decrypted: '%s'\n", decrypted)
	}

	if hexin != "" {

		if hexin[:2] == "0x" {
			hexin = hexin[2:]
		}

		bb, err := hex.DecodeString(hexin)
		if err != nil {
			log.Fatal(err)
		}
		decrypted, err := nativeprotect.Unprotect(bb)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("decrypted: '%s'\n", decrypted)
	}
}
