package services

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	model "cvedict/model"
)

func writeToOutput(cve model.Cve, path string, wg *sync.WaitGroup) {
	defer wg.Done()
	if path == "" { // stdout
		s, _ := json.MarshalIndent(cve, "", "\t")
		fmt.Println(string(s))
	} else { // write to file
		if path[0] == '~' { // expand tilde
			home, _ := os.UserHomeDir()
			path = filepath.Join(home, strings.Replace(path, "~", "", 1))
		}

		// create dir if not exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			os.MkdirAll(path, 0755)
		}

		filename := fmt.Sprintf("%s/%s.json", path, cve.Id)
		s, _ := json.MarshalIndent(cve, "", "\t")
		os.WriteFile(filename, s, 0644)
	}
}
