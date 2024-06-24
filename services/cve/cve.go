package cve

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"

	model "cvedict/model"
)

func WriteToFile(cve model.Cve, filename string) {
	if filename == "" {
		// set default name for local file if not filename passed in
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

func ReadFromFile(filename string) model.Cve {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	var cve model.Cve
	err = json.Unmarshal(data, &cve)
	if err != nil {
		log.Fatal(err)
	}
	return cve
}
