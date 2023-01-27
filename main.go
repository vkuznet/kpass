package main

// kpass - command line interface for KeePass
//
// Copyright (c) 2023 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"time"
)

// version of the code
var gitVersion, gitTag string

// ecmInfo function returns version string of the server
func kpassInfo() string {
	goVersion := runtime.Version()
	tstamp := time.Now().Format("2006-02-01")
	return fmt.Sprintf("kpass git=%s tag=%s go=%s date=%s", gitVersion, gitTag, goVersion, tstamp)
}

// helper function to print commands usage
func cmdUsage(dbPath string) {
	if dbPath != "" {
		info, err := os.Stat(dbPath)
		if err == nil {
			fmt.Println()
			fmt.Println("Database            : ", dbPath)
			fmt.Println("Size                : ", sizeFormat(info.Size()))
			fmt.Println("Modification time   : ", info.ModTime())
		}
	}
	fmt.Println()
	fmt.Println("KeePass DB commands :")
	fmt.Println("cp <ID> <attribute> # copy record ID attribute to cpilboard")
	fmt.Println("rm <ID>             # remove record ID from database")
	fmt.Println("add <key>           # add specific record key")
	fmt.Println("save                # save record in DB and write new DB file")
	fmt.Println("timeout             # show current timeout settings")
	fmt.Println("timeout <int>       # set timeout interval in seconds")
	fmt.Println()
	fmt.Println("Additional commands :")
	fmt.Println("encrypt <fname>     # encrypt given file")
	fmt.Println("decrypt <fname>     # decrypt given file")
	fmt.Println("help                # show this message")
}

// main function
func main() {
	usr, _ := user.Current()
	defaultPath := fmt.Sprintf("%s/.keepass.kdbx", usr.HomeDir)

	var kfile, kpath string
	flag.StringVar(&kpath, "kdbx", defaultPath, "path to kdbx file")
	flag.StringVar(&kfile, "kfile", "", "key file name")
	var interval int
	flag.IntVar(&interval, "interval", 30, "timeout interval in seconds")
	var pwd string
	flag.StringVar(&pwd, "pwd", "", "generate password with given length:attributes. Attributes can be 'n' (numbers), s' (symbols) or their combinations), e.g. 16:ns will provide password of length 16 with numbers and symbols in it")
	var version bool
	flag.BoolVar(&version, "version", false, "show version")
	var cipher string
	flag.StringVar(&cipher, "cipher", "aes", "cipher to use (aes, nacl)")
	var dfile string
	flag.StringVar(&dfile, "decrypt", "", "decrypt given file")
	var efile string
	flag.StringVar(&efile, "encrypt", "", "encrypt given file")
	flag.Usage = func() {
		fmt.Println("Usage: kpass [options]")
		flag.PrintDefaults()
		cmdUsage("")
	}
	flag.Parse()
	if version {
		fmt.Println(kpassInfo())
		os.Exit(0)
	}

	// test keyfile functionality
	/*
		if kfile != "" {
			keyFile, err := readKeyFile(kfile)
			if err == nil {
				log.Printf("keyfile %+v", keyFile)
			} else {
				log.Fatal(err)
			}
			err = writeKeyFile(keyFile, "/tmp/keyfile.keyx")
			if err != nil {
				log.Fatal(err)
			}
			return
		}
	*/

	// generate password if asked
	if pwd != "" {
		genPassword(pwd)
		return
	}
	// decrypt given file
	if dfile != "" {
		decryptFile(dfile, cipher)
		return
	}
	// encrypt given file
	if efile != "" {
		encryptFile(efile, cipher)
		return
	}
	manageKeePass(kpath, kfile, pwd, interval)
}
