package main

// kpass - command line interface for KeePass
//
// Copyright (c) 2023 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/vkuznet/cryptoutils"
)

// helper function to generate password
func genPassword(pwd string) {
	arr := strings.Split(pwd, ":")
	i, e := strconv.Atoi(arr[0])
	if e != nil {
		log.Fatal(e)
	}
	var numbers, symbols bool
	if strings.Contains(pwd, "n") {
		numbers = true
	}
	if strings.Contains(pwd, "s") {
		symbols = true
	}
	p := cryptoutils.CreatePassword(i, numbers, symbols)
	copy2clipboard(p, fmt.Sprintf("New password %s copied to clipboard", p))
}

// helper function to encrypt or decrypt given file
func cryptFile(fname, kfile, cipher, action string) {
	password := readPassword("Enter password: ")
	data, err := os.ReadFile(fname)
	if err != nil {
		log.Fatal(err)
	}
	// if key file is given we'll use KeyFile data value and its hash to
	// enhance the password
	if kfile != "" {
		if keyFile, err := readKeyFile(kfile); err == nil {
			password = fmt.Sprintf("%s-%s-%s", password, keyFile.Key.Data.Value, keyFile.Key.Data.Hash)
		} else {
			log.Fatal(err)
		}
	}
	var oname string
	if action == "decrypt" {
		data, err = cryptoutils.Decrypt(data, password, cipher)
		oname = fmt.Sprintf("%s-decrypted", fname)
	} else if action == "encrypt" {
		data, err = cryptoutils.Encrypt(data, password, cipher)
		oname = fmt.Sprintf("%s-encrypted", fname)
	} else {
		log.Fatalf("unsupported action %s\n", action)
	}
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(oname, data, 0755)
	if err != nil {
		log.Fatal("unable to data to output file", err)
	}
	if action == "encrypt" {
		log.Printf("encrypted %s to %s\n", fname, oname)
	} else if action == "decrypt" {
		log.Printf("decrypted %s to %s\n", fname, oname)
	} else {
		log.Fatalf("unsupported action %s\n", action)
	}
}

// encryptFile encrypt given file
func encryptFile(fname, kfile, cipher string) {
	cryptFile(fname, kfile, cipher, "encrypt")
}

// decryptFile decrypt given file
func decryptFile(fname, kfile, cipher string) {
	cryptFile(fname, kfile, cipher, "decrypt")
}
