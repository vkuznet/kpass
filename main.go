package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/atotto/clipboard"
	gokeepasslib "github.com/tobischo/gokeepasslib/v3"
	wrappers "github.com/tobischo/gokeepasslib/v3/wrappers"
	"golang.org/x/crypto/ssh/terminal"
)

// DBRecords defines map of DB records
type DBRecords map[int]gokeepasslib.Entry

// Record represent record map
type Record map[string]string

// keep track if user requested password field
var inputPwd bool

// global db records
var dbRecords DBRecords

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
			fmt.Println()
		}
	} else {
		fmt.Println()
	}
	fmt.Println("Commands within DB")
	fmt.Println("cp <ID> <attribute> # to copy record ID attribute to cpilboard")
	fmt.Println("rm <ID>             # to remove record ID from database")
	fmt.Println("add <key>           # to add specific record key")
	fmt.Println("save record         # to save record in DB and write new DB file")
	fmt.Println("timeout <int>       # set timeout interval in seconds")
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

	// generate password if asked
	if pwd != "" {
		genPassword(pwd)
		os.Exit(0)
	}
	manageKeePass(kpath, kfile, pwd, interval)
}

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
	p := CreatePassword(i, numbers, symbols)
	copy2clipboard(p, fmt.Sprintf("New password %s copied to clipboard", p))
}

// helper function to mange KeePass database
func manageKeePass(kpath, kfile, pwd string, interval int) {

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
	//     patSave, err := regexp.Compile(`save record`)
	//     if err != nil {
	//         log.Fatal(err)
	//     }
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
			if input == "save record" {
				saveRecord(kpath, kfile, pwd, db, rec)
				rec = nil
				collectKey = ""
				inputMsg = inputMsgOrig
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
			} else if matched := patCopy.MatchString(input); matched {
				clipboardCopy(input)
				inputMsg = inputMsgOrig
			} else if matched := patRemove.MatchString(input); matched {
				removeRecord(input)
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

// helper function to copy content to clipboard
func copy2clipboard(val, msg string) {
	if err := clipboard.WriteAll(val); err != nil {
		log.Fatal(err)
	}
	if msg != "" {
		fmt.Println(msg)
	}
}

// helper function to remove record from the database
func removeRecord(input string) {
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
	var err error

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

// helper function to read from stdin
func readInput() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	val, err := reader.ReadString('\n')
	return val, err
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
