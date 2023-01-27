package main

// Based on: https://tutorialedge.net/golang/parsing-xml-with-golang/

import (
	"encoding/xml"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
)

// KeyFile represents key file structure
type KeyFile struct {
	XMLName xml.Name `xml:"KeyFile"`
	Key     Key      `xml:"Key"`
	Meta    Meta     `xml:"Meta"`
}

// Key represents Key structure within KeyFile
type Key struct {
	XMLName xml.Name `xml:"Key"`
	Data    Data     `xml:"Data"`
}

// Data represents Data structure within Data xml object
type Data struct {
	Hash  string `xml:"Hash,attr"`
	Value string `xml:",chardata"`
}

// Meta represents Meta structure within KeyFile
type Meta struct {
	XMLName xml.Name `xml:"Meta"`
	Version string   `xml:"Version"`
}

// helper function to parse key file
func readKeyFile(fname string) (KeyFile, error) {
	var keyFile KeyFile

	// Open our xmlFile
	xmlFile, err := os.Open(fname)
	if err != nil {
		return keyFile, err
	}
	defer xmlFile.Close()

	// read our opened xmlFile as a byte array.
	byteValue, err := ioutil.ReadAll(xmlFile)
	if err != nil {
		return keyFile, err
	}

	// unmarshal the data
	err = xml.Unmarshal(byteValue, &keyFile)

	// strip off newlines in Data
	val := keyFile.Key.Data.Value
	val = strings.Replace(val, "\n", "", -1)
	if regex, err := regexp.Compile("[  ]+"); err == nil {
		val = regex.ReplaceAllString(val, " ")
	}
	val = strings.Trim(val, " ")
	keyFile.Key.Data.Value = val
	return keyFile, err
}

// helper function to write keyfile
func writeKeyFile(keyFile KeyFile, fname string) error {
	data, err := xml.MarshalIndent(keyFile, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer file.Close()
	file.Write(data)
	return nil
}
