package main

import (
	"bytes"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"

	_ "github.com/jdeng/go-sqlcipher"
)

func getImei(fn string) (string, error) {
	bs, err := ioutil.ReadFile(fn)
	if err != nil {
		return "", err
	}

	key := []byte{0x73, 0x71, 0x00, 0x7e, 0x00, 0x02, 0x00, 0x00, 0x01, 0x02, 0x74}
	if pos := bytes.Index(bs, key); pos > 0 {
		bs = bs[pos+len(key):]
		if len(bs) > 2 {
			size := (int(bs[0])<<8 + int(bs[1]))
			bs = bs[2:]
			if len(bs) >= size {
				s := string(bs[:size])
				return s, nil
			}
		}
	}
	return "", fmt.Errorf("IMEI not found")
}

func getUin(fn string) (uins []int32, err error) {
	var bs []byte
	if bs, err = ioutil.ReadFile(fn); err != nil {
		return
	}

	key := []byte{0x73, 0x71, 0x00, 0x7e, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01} //, 0x73, 0x71, 0x00, 0x7e, 0x00, 0x02, 0x87, 0xe6, 0xe3, 0x08
	prefix := []byte{0x73, 0x71, 0x00, 0x7e, 0x00, 0x02}

	for {
		pos := bytes.Index(bs, key)
		if pos < 0 {
			break
		}
		bs = bs[pos+len(key):]
		if bytes.HasPrefix(bs, prefix) && len(bs) > 10 {
			bs = bs[6:]
			uin := int32((uint32(bs[0]) << 24) + (uint32(bs[1]) << 16) + (uint32(bs[2]) << 8) + uint32(bs[3]))
			uins = append(uins, uin)
			log.Printf("%d\n", uin)
			bs = bs[4:]
		}
	}

	if len(uins) == 0 {
		err = fmt.Errorf("Uin not found")
	}
	return
}

func md5sum(s string) string {
	hasher := md5.New()
	hasher.Write([]byte(s))
	return hex.EncodeToString(hasher.Sum(nil))
}

func getKey(dir string) (key string, err error) {
	//	var uins []int32
	imei, err := getImei(filepath.Join(dir, "CompatibleInfo.cfg"))
	if err != nil {
		log.Println("CompatibleInfo.cfg not found\n")
		return
	}

	uins, err := getUin(filepath.Join(dir, "systemInfo.cfg"))
	if err != nil || len(uins) == 0 {
		return
	}

	uin := uins[0]
	token := fmt.Sprintf("%s%d", imei, uin)
	key = md5sum(token)[:7]
	dir = md5sum(fmt.Sprintf("mm%d", uin))
	log.Println("token: ", token, ", key:", key, ", dir name: ", dir)

	return
}

func convertDatabase(dbfile string, key string, disableHmac bool, outfile string) error {
	db, err := sql.Open("sqlcipher", dbfile)
	if err != nil {
		log.Printf("Failed to open %s. Error: %v\n", dbfile, err)
		return err
	}
	defer db.Close()

	_, err = db.Exec(fmt.Sprintf("PRAGMA key=\"%s\";", key))
	if err != nil {
		log.Printf("Failed to assign key %s. Error: %v\n", key, err)
		return err
	}

	if disableHmac {
		_, err = db.Exec("PRAGMA cipher_use_hmac=off;")
		if err != nil {
			log.Printf("Failed to turn of hmac. Error: %v\n", err)
			return err
		}
	}

	_, err = db.Exec("SELECT count(1) FROM sqlite_master;")
	if err != nil {
		log.Printf("Failed to execute test query. Error: %v\n", err)
		return err
	}

	log.Printf("Converting database %s to %s\n", dbfile, outfile)

	_, err = db.Exec(fmt.Sprintf("ATTACH DATABASE '%s' AS pt KEY '';", outfile))
	if err != nil {
		log.Printf("Failed to attach database %s. Error: %v\n", outfile, err)
		return err
	}

	_, err = db.Exec("SELECT sqlcipher_export('pt');")
	if err != nil {
		log.Printf("Failed to decipher. Error: %v\n", err)
		return err
	}

	_, err = db.Exec("DETACH DATABASE pt;")
	if err != nil {
		log.Printf("Failed to detach database. Error: %v\n", err)
		return err
	}

	log.Printf("Successfully converted database %s to %s\n", dbfile, outfile)
	return nil
}

var (
	dbFile = flag.String("db", "", "db file")
	dbKey  = flag.String("key", "", "db key")
	dbOut  = flag.String("out", "", "output db file")
)

func main() {
	flag.Parse()
	if *dbFile == "" || *dbOut == "" {
		log.Fatal("No file specified")
	}

	dbfile := *dbFile
	var disableHmac bool
	if *dbKey == "" {
		dir := filepath.Dir(dbfile)
		*dbKey, _ = getKey(dir)
		disableHmac = true
	} else {
		*dbKey = fmt.Sprintf("x'%s'", *dbKey)
		log.Printf("%s\n", *dbKey)
	}
	convertDatabase(dbfile, *dbKey, disableHmac, *dbOut)
}
