# kpass, command line client (CLI) for [KeePass](https://keepass.info/)

[![Build Status](https://github.com/vkuznet/kpass/actions/workflows/go.yml/badge.svg)](https://github.com/vkuznet/kpass/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/vkuznet/kpass)](https://goreportcard.com/report/github.com/vkuznet/kpass)
[![GoDoc](https://godoc.org/github.com/vkuznet/kpass?status.svg)](https://godoc.org/github.com/vkuznet/kpass)

The `kpass` CLI tool is designed to work with your favorite [KeePass](https://keepass.info/)
database using terminal only. It supports all major architecures, including
Linux, Windows, and macOS. It can work with kdbx and key files. It allows
to search for your records using matchign string or regular expressions,
as well as create and delete records in your KeePass database. Below you can
find a few examples which demonstrate its functionality.

```
# start kpass tool with your favorite DB
./kpass -kdbx TestDB.kdbx

db password:

Database            :  /Users/vk/TestDB.kdbx
Size                :  1605 (1.6KB)
Modification time   :  2023-01-22 08:40:44.312638212 -0500 EST

Commands within DB
cp <ID> <attribute> # to copy record ID attribute to cpilboard
rm <ID>             # to remove record ID from database
add <key>           # to add specific record key
save record         # to save record in DB and write new DB file
timeout <int>       # set timeout interval in seconds
Welcome to Root (1 records)

db #
```
Now, you can search for your records, e.g.
```
db # GMail

db #
---
Record   1
Title    GMail
UserName example@gmail.com
URL      https://goolge.com/
Notes    some note about GMail account
Tags     email
```
or, you may create a new record
```
db # add login
login value: TestLogin

db # add password
set encrypted input for password field
password value:
repeat password:

db # save record
2023/01/25 15:51:35 Wrote kdbx file: /Users/vk/TestDB.kdbx-new
```
