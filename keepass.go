package main

// kpass - command line interface for KeePass
//
// Copyright (c) 2023 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	gokeepasslib "github.com/tobischo/gokeepasslib/v3"
	wrappers "github.com/tobischo/gokeepasslib/v3/wrappers"
)

// DBRecords defines map of DB records
type DBRecords map[int]gokeepasslib.Entry

// Record represent record map
type Record map[string]string

// keep track if user requested password field
var inputPwd bool

// global db records
var dbRecords DBRecords

// helper function to mange KeePass database
func manageKeePass(kpath, kfile, pwd, cipher string, interval int) {

	file, err := os.Open(kpath)
	if err != nil {
		log.Fatal(err)
	}

	db := gokeepasslib.NewDatabase()
	pwd = readPassword("db password: ")
	if kfile != "" {
		db.Credentials, err = gokeepasslib.NewPasswordAndKeyCredentials(pwd, kfile)
		if err != nil {
			log.Fatalf("ERROR: unable to get credentials, %v", err)
		}
	} else {
		db.Credentials = gokeepasslib.NewPasswordCredentials(pwd)
	}
	_ = gokeepasslib.NewDecoder(file).Decode(db)
	if db.Content.Root == nil {
		msg := "ERROR: wrong password"
		log.Fatal(msg)
	}
	db.UnlockProtectedEntries()

	time0 := time.Now()
	timeout := time.Duration(interval) * time.Second
	err = readDB(db)
	if err != nil {
		log.Fatal(err)
	}

	// proceed with db records
	cmdUsage(kpath)
	var names []string
	for _, g := range db.Content.Root.Groups {
		names = append(names, g.Name)
	}
	fmt.Printf("Welcome to %s (%d records)", strings.Join(names, ","), len(dbRecords))

	inputMsg := "\ndb # "
	inputMsgOrig := inputMsg
	inputPwd = false
	fmt.Printf(inputMsg)

	// we'll read out std input via goroutine
	ch := make(chan string)
	go readInputChannel(ch)

	// read stdin and search for DB record
	patCopy, err := regexp.Compile(`cp [0-9]+`)
	if err != nil {
		log.Fatal(err)
	}
	patRemove, err := regexp.Compile(`rm [0-9]+`)
	if err != nil {
		log.Fatal(err)
	}
	patAdd, err := regexp.Compile(`add [a-zA-Z]+`)
	if err != nil {
		log.Fatal(err)
	}
	patEncrypt, err := regexp.Compile(`encrypt [0-9]+`)
	if err != nil {
		log.Fatal(err)
	}
	patDecrypt, err := regexp.Compile(`decrypt [0-9]+`)
	if err != nil {
		log.Fatal(err)
	}
	patTimeout, err := regexp.Compile(`timeout [0-9]+`)
	if err != nil {
		log.Fatal(err)
	}

	// main loop
	var rec Record
	rec = nil
	collectKey := ""
	for {
		select {
		case input := <-ch:
			input = strings.Replace(input, "\n", "", -1)
			if input == "save" {
				saveRecord(kpath, kfile, pwd, db, rec)
				rec = nil
				collectKey = ""
				inputMsg = inputMsgOrig
			} else if input == "timeout" {
				fmt.Println("Current DB timeout is", timeout, " seconds")
			} else if input == "exit" || input == "quit" {
				os.Exit(0)
			} else if strings.HasPrefix(input, "WARNING") {
				collectKey = ""
				fmt.Println(input)
				inputMsg = inputMsgOrig
			} else if collectKey != "" {
				rec[collectKey] = input
				collectKey = ""
				inputMsg = inputMsgOrig
			} else if matched := patEncrypt.MatchString(input); matched {
				fname := strings.Replace(input, "encrypt", "", -1)
				fname = strings.Trim(fname, " ")
				encryptFile(fname, kfile, cipher)
			} else if matched := patDecrypt.MatchString(input); matched {
				fname := strings.Replace(input, "encrypt", "", -1)
				fname = strings.Trim(fname, " ")
				decryptFile(fname, kfile, cipher)
			} else if matched := patCopy.MatchString(input); matched {
				clipboardCopy(input)
				inputMsg = inputMsgOrig
			} else if matched := patRemove.MatchString(input); matched {
				if rid, err := strconv.Atoi(input); err == nil {
					removeRecord(kpath, kfile, pwd, db, rid)
				} else {
					log.Printf("ERROR: unable to parse record id, error: %v", err)
				}
				inputMsg = inputMsgOrig
			} else if matched := patAdd.MatchString(input); matched {
				if rec == nil {
					rec = make(map[string]string)
				}
				collectKey = strings.Replace(input, "add ", "", -1)
				if strings.ToLower(collectKey) == "password" {
					inputPwd = true
					fmt.Println("set encrypted input for password field")
				}
				inputMsg = fmt.Sprintf("%s value: ", collectKey)
			} else if matched := patTimeout.MatchString(input); matched {
				vvv := strings.Trim(strings.Replace(input, "timeout ", "", -1), " ")
				if val, err := strconv.Atoi(vvv); err == nil {
					timeout = time.Duration(val)
					fmt.Printf("New DB timeout is set to %d seconds", timeout)
				}
				inputMsg = inputMsgOrig
			} else {
				search(input)
				inputMsg = inputMsgOrig
			}
			time0 = time.Now()
			fmt.Printf(inputMsg)
		default:
			if time.Since(time0) > timeout {
				fmt.Printf("\nExit after %s of inactivity", time.Since(time0))
				os.Exit(1)
			}
			time.Sleep(time.Duration(1) * time.Millisecond) // wait for new input
		}
	}
}

// helper function to remove record from the database
func removeRecord(dbPath, kfile, pwd string, db *gokeepasslib.Database, rid int) {
	// find our record for given input
	recEntry := dbRecords[rid]

	// iterate over existing db entries and add it to our group
	// but skip our record entry corresponding to given record id
	group := gokeepasslib.NewGroup()
	// iterate over existing db entries and add it to our group
	for _, top := range db.Content.Root.Groups {
		group.Name = top.Name
		for _, entry := range top.Entries {
			if entry.UUID != recEntry.UUID {
				group.Entries = append(group.Entries, entry)
			}
		}
		for _, groups := range top.Groups {
			for _, entry := range groups.Entries {
				if entry.UUID != recEntry.UUID {
					group.Entries = append(group.Entries, entry)
				}
			}
		}
	}

	// write new database file
	writeNewDB(dbPath, kfile, pwd, group)
}

// helper function to make entry db value
func mkValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{Key: key, Value: gokeepasslib.V{Content: value}}
}

// helper function to make protected entry db value
func mkProtectedValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{
		Key:   key,
		Value: gokeepasslib.V{Content: value, Protected: wrappers.NewBoolWrapper(true)},
	}
}

// helper function to save record to the database
func saveRecord(dbPath, kfile, pwd string, db *gokeepasslib.Database, rec Record) {

	// add Title to record if it is missing
	if _, ok := rec["Title"]; !ok {
		rec["Title"] = "Record"
	}

	// create new group and entry objects
	group := gokeepasslib.NewGroup()
	entry := gokeepasslib.NewEntry()

	// iterate over existing db entries and add it to our group
	for _, top := range db.Content.Root.Groups {
		group.Name = top.Name
		for _, entry := range top.Entries {
			group.Entries = append(group.Entries, entry)
		}
		for _, groups := range top.Groups {
			for _, entry := range groups.Entries {
				group.Entries = append(group.Entries, entry)
			}
		}
	}

	// now we'll add our new record to group entries
	for key, val := range rec {
		attr := strings.ToLower(key)
		if attr == "password" {
			entry.Values = append(entry.Values, mkProtectedValue("Password", val))
		} else {
			key = strings.Title(key)
			if attr == "username" {
				key = "UserName"
			}
			entry.Values = append(entry.Values, mkValue(key, val))
		}
	}

	// add entry to our db records object
	rid := len(dbRecords) + 1
	dbRecords[rid] = entry

	// update db group entries
	group.Entries = append(group.Entries, entry)

	// write new database file
	writeNewDB(dbPath, kfile, pwd, group)
}

// helper function to write new database file with given group
func writeNewDB(dbPath, kfile, pwd string, group gokeepasslib.Group) {

	var err error

	// write group entries to DB
	// https://github.com/tobischo/gokeepasslib/blob/master/examples/writing/example-writing.go
	creds := gokeepasslib.NewPasswordCredentials(pwd)
	if kfile != "" {
		creds, err = gokeepasslib.NewPasswordAndKeyCredentials(pwd, kfile)
		if err != nil {
			log.Fatal(err)
		}
	}
	newdb := &gokeepasslib.Database{
		Header:      gokeepasslib.NewHeader(),
		Credentials: creds,
		Content: &gokeepasslib.DBContent{
			Meta: gokeepasslib.NewMetaData(),
			Root: &gokeepasslib.RootData{
				Groups: []gokeepasslib.Group{group},
			},
		},
	}
	filename := fmt.Sprintf("%s-new", dbPath)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// Lock entries using stream cipher
	newdb.LockProtectedEntries()

	// and encode it into the file
	keepassEncoder := gokeepasslib.NewEncoder(file)
	if err := keepassEncoder.Encode(newdb); err != nil {
		log.Fatal(err)
	}
	log.Printf("Wrote kdbx file: %s", filename)
	//     db.UnlockProtectedEntries()
}

// helper function to get value of kdbx record
func getValue(entry gokeepasslib.Entry, key string) string {
	if ptr := entry.Get(key); ptr != nil {
		if ptr.Key == key {
			return fmt.Sprintf("%+v", ptr.Value.Content)
		}
	}
	return ""
}

// helper function to read db records
func readDB(db *gokeepasslib.Database) error {
	if dbRecords == nil {
		dbRecords = make(DBRecords)
	}

	rid := 0
	for _, top := range db.Content.Root.Groups {
		if top.Name == "NewDatabase" {
			msg := "ERROR: wrong password or empty database"
			return errors.New(msg)
		}
		for _, entry := range top.Entries {
			dbRecords[rid] = entry
			rid += 1
		}
		for _, groups := range top.Groups {
			for _, entry := range groups.Entries {
				dbRecords[rid] = entry
				rid += 1
			}
		}
	}
	return nil
}

// helper function to search for given input
func search(input string) {
	keys := []string{"UserName", "URL", "Notes", "Login", "Email"}
	pat := regexp.MustCompile(input)
	for rid, entry := range dbRecords {
		if strings.Contains(entry.GetTitle(), input) ||
			strings.Contains(entry.Tags, input) {
			printRecord(rid, entry)
		} else {
			for _, k := range keys {
				val := getValue(entry, k)
				if pat.MatchString(val) {
					printRecord(rid, entry)
				}
			}
		}
	}
}

// helper function to print record
func printRecord(pid int, entry gokeepasslib.Entry) {
	fmt.Printf("---\n")
	fmt.Printf("Record   %d\n", pid)
	fmt.Printf("Title    %s\n", getValue(entry, "Title"))
	fmt.Printf("Login    %s\n", getValue(entry, "Login"))
	fmt.Printf("UserName %s\n", getValue(entry, "UserName"))
	fmt.Printf("URL      %s\n", getValue(entry, "URL"))
	fmt.Printf("Notes    %s\n", getValue(entry, "Notes"))
	fmt.Printf("Tags     %s\n", entry.Tags)
}
