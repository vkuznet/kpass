package main

// kpass - command line interface for KeePass
//
// Copyright (c) 2023 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/atotto/clipboard"
	"golang.org/x/crypto/ssh/terminal"
)

// helper function to convert size into human readable form
func sizeFormat(val int64) string {
	size := float64(val)
	base := 1000. // CMS convert is to use power of 10
	xlist := []string{"", "KB", "MB", "GB", "TB", "PB"}
	for _, vvv := range xlist {
		if size < base {
			return fmt.Sprintf("%v (%3.1f%s)", val, size, vvv)
		}
		size = size / base
	}
	return fmt.Sprintf("%v (%3.1f%s)", val, size, xlist[len(xlist)])
}

// helper function to read from stdin
func readInput() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	val, err := reader.ReadString('\n')
	return val, err
}

// helper function to get password from stdin
func readPassword(msg string) string {
	if msg != "" {
		fmt.Print(msg)
	}
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err == nil {
		fmt.Println("")
	} else {
		fmt.Println("\nError in ReadPassword", err)
		os.Exit(1)
	}
	password := string(bytePassword)
	return strings.TrimSpace(password)
}

// helper function to read stdin and send it over provided channel
// https://stackoverflow.com/questions/50788805/how-to-read-from-stdin-with-goroutines-in-golang
func readInputChannel(ch chan<- string) {
	var val string
	var err error
	for {
		msg := ""
		if inputPwd == true {
			val = readPassword("")
			// read password again to match it
			if v := readPassword("repeat password: "); v != val {
				msg = fmt.Sprintf("WARNING: password match failed, will discard it ...")
			}
		} else {
			val, err = readInput()
			if err != nil {
				msg = fmt.Sprintf("WARNING: wrong input %v", err)
			}
		}
		inputPwd = false
		if msg != "" {
			ch <- msg
		} else {
			ch <- val
		}
		time.Sleep(time.Duration(1) * time.Millisecond) // wait for new input
	}
}

// helper function to copy content to clipboard
func copy2clipboard(val, msg string) {
	if err := clipboard.WriteAll(val); err != nil {
		log.Fatal(err)
	}
	if msg != "" {
		fmt.Println(msg)
	}
}

// helper function to copy to clipboard db record attribute
func clipboardCopy(input string) {
	// the input here is cp <ID> attribute
	arr := strings.Split(input, " ")
	if len(arr) < 2 {
		log.Printf("WARNING: unable to parse command '%s'", input)
		return
	}
	rid, err := strconv.Atoi(arr[1])
	if err != nil {
		log.Println("Unable to get record ID", err)
		return
	}
	attr := "password"
	if len(arr) == 3 {
		attr = strings.ToLower(arr[2])
	}
	var val string
	if entry, ok := dbRecords[rid]; ok {
		if attr == "password" {
			val = entry.GetPassword()
		} else if attr == "title" {
			val = getValue(entry, "Title")
		} else if attr == "username" {
			val = getValue(entry, "UserName")
		} else if attr == "login" {
			val = getValue(entry, "Login")
		} else if attr == "email" {
			val = getValue(entry, "EMail")
		} else if attr == "url" {
			val = getValue(entry, "URL")
		} else if attr == "notes" {
			val = getValue(entry, "Notes")
		}
		if val != "" {
			msg := fmt.Sprintf("%s copied to clipboard", attr)
			copy2clipboard(string(val), msg)
		}
	}
}
