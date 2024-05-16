package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"go.mongodb.org/mongo-driver/bson"

	db "cve-dict/database"
	"cve-dict/model"
)

const (
	GIT_REPO_URL = "https://github.com/fkie-cad/nvd-json-data-feeds.git"
	LOCAL_DIR    = "/.config/cvedb/nvdcve"
)

func localRepoPath() string {
	path, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	return path + LOCAL_DIR
}

func cloneRepo(localPath string) *git.Repository {
	fmt.Printf("Cloning repo to %s\n", localPath)
	repo, err := git.PlainClone(localPath, false, &git.CloneOptions{
		URL:      GIT_REPO_URL,
		Progress: os.Stdout,
	})
	if err == git.ErrRepositoryAlreadyExists {
		fmt.Println("Repo already exists, pulling...")
		repo, err = git.PlainOpen(localPath)
		if err != nil {
			log.Fatal(err)
		}
	} else if err != nil {
		log.Fatal(err)
	}
	return repo
}

func pull(repo *git.Repository) error {
	wt, err := repo.Worktree()
	if err != nil {
		panic(err)
	}

	err = wt.Pull(&git.PullOptions{
		Progress: os.Stdout,
	})

	return err
}

func getUpdatedFiles(oldCommit, newCommit *object.Commit) []string {
	patch, err := oldCommit.Patch(newCommit)
	if err != nil {
		log.Fatal(err)
	}
	var files []string
	for _, filePatch := range patch.FilePatches() {
		from, to := filePatch.Files()
		if from != nil && to != nil {
			files = append(files, to.Path()) // modified
		} else if from != nil {
			files = append(files, from.Path()) // deleted
		} else if to != nil {
			files = append(files, to.Path()) // added
		}
	}
	return files[:]
}

func getCurrentHash(repo *git.Repository) (*plumbing.Hash, error) {
	hash, err := repo.ResolveRevision(plumbing.Revision("HEAD"))
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func filterFiles(files []string, path string, pattern string) []string {
	var filteredFiles []string = []string{}
	if files != nil {
		// when new files are pulled
		for _, f := range files {
			match, err := filepath.Match(pattern, filepath.Base(f))
			if err != nil {
				log.Fatal(err)
			}
			if match {
				filteredFiles = append(filteredFiles, localRepoPath()+"/"+f)
			}
		}
	} else if path != "" {
		// when repo is cloned
		err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			match, _ := filepath.Match(pattern, filepath.Base(path))
			if match {
				filteredFiles = append(filteredFiles, path)
			}

			return nil
		})
		if err != nil {
			log.Fatal(err)
		}
	} else if pattern == "" {
		panic("Please provide pattern")
	}
	return filteredFiles
}

func readJson(path string) []byte {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}
	return data
}

// json2Cve reads JSON files from the provided paths, unmarshals them into model.Cve objects, and returns a slice of model.Cve.
//
// paths: a slice of strings representing the file paths of the JSON files to read.
// []model.Cve: a slice of model.Cve objects unmarshaled from the JSON files.
func json2Cve(paths []string) []model.Cve {
	var cves []model.Cve

	// read JSON files => unmarshal into `cve` => store in `cves`
	for _, path := range paths {
		data := readJson(path)

		var cveJson *model.Cve = new(model.Cve)
		if err := json.Unmarshal(data, cveJson); err != nil {
			fmt.Printf("Unable to parse JSON file: %s\nError: %s\n", path, err)
			continue
		}
		cves = append(cves, *cveJson)
	}

	return cves
}

func localCves() []string {
	var cveFilePaths []string = []string{}
	repo := cloneRepo(localRepoPath())

	hash1, err := getCurrentHash(repo)
	if err != nil {
		log.Fatal(err)
	}

	err = pull(repo)
	if err != git.NoErrAlreadyUpToDate {
		hash2, err := getCurrentHash(repo)
		if err != nil {
			log.Fatal(err)
		}

		c1, _ := repo.CommitObject(*hash1)
		c2, _ := repo.CommitObject(*hash2)
		cveFilePaths = getUpdatedFiles(c1, c2)
		cveFilePaths = filterFiles(cveFilePaths, "", "CVE-*.json")
	} else {
		fmt.Println(git.NoErrAlreadyUpToDate)
		cveFilePaths = filterFiles(nil, localRepoPath(), "CVE-*.json")
	}
	return cveFilePaths
}

func main() {
	cveFilePaths := localCves()
	// fmt.Println(reflect.TypeOf(cveFilePaths))
	// fmt.Println(len(cveFilePaths))
	fmt.Printf("Total: %d CVE JSON files found\n", len(cveFilePaths))

	cves := json2Cve(cveFilePaths)
	// cves := json2Cve(nil) // DEBUG Purposes
	fmt.Printf("Total: %d CVEs loaded\n", len(cves))

	client := db.Connect("")

	// insert many
	var bDocs []interface{}
	for _, c := range cves {
		var bdoc interface{}
		bdoc, err := bson.Marshal(c)
		if err != nil {
			log.Fatal(err)
		}
		bDocs = append(bDocs, bdoc)
	}

	//! InsertMany sometime stop/pause inserting
	//! Two Errors:
	//! 1.unable to write wire message to network: write tcp [::1]:60067->[::1]:27100: write: broken pipe
	//! 2.socket was unexpectedly closed: EOF
	//! Errors disappear on 16/05/2024, keep this comment for reference
	db.InsertMany(*client, "test", "fortest", bDocs)

	db.Disconnect(*client)
}
