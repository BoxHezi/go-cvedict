package cve

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	model "cve-dict/model"
)

func WriteToFile(cve model.Cve, filename string) {
	if filename == "" {
		filename = cve.GenerateFilename()
	}
	parentDir := filepath.Dir(filename)
	// create dir if not exists
	if _, err := os.Stat(parentDir); os.IsNotExist(err) {
		os.MkdirAll(parentDir, 0755)
	}

	file, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	data, err := json.Marshal(cve)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func GetCveById(id string) model.Cve {
	var cve model.Cve = model.Cve{
		Id: id,
	}
	filename := cve.GenerateFilename()

	file, err := os.Open(filename)
	if err != nil {
		err = fmt.Errorf("local cve json file not found: %s", err)
		log.Fatal(err)
	}
	defer file.Close()

	data, err := io.ReadAll(file) // read local CVE json file
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(data, &cve)
	if err != nil {
		log.Fatal(err)
	}
	return cve
}