package main

import (
	"fmt"
	"log"
	"os"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

const (
	gitRepoUrl      = "https://github.com/fkie-cad/nvd-json-data-feeds.git"
	localDirSuffix  = "/.config/cvedb/nvdcve"
	filenamePattern = "CVE-*.json"

	statusModified = "modified"
	statusDeleted  = "deleted"
	statusAdded    = "added"
)

func localRepoPath() string {
	path, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	return path + localDirSuffix
}

func cloneRepo(localPath string) (*git.Repository, error) {
	fmt.Printf("Cloning repo to %s\n", localPath)
	repo, err := git.PlainClone(localPath, false, &git.CloneOptions{
		URL:      gitRepoUrl,
		Progress: os.Stdout,
		// Depth:    1,
	})

	if err == git.ErrRepositoryAlreadyExists {
		repo, err = git.PlainOpen(localPath)
		if err != nil {
			log.Fatal(err)
		}
		err = git.ErrRepositoryAlreadyExists
	} else if err != nil {
		log.Fatal(err)
	}
	// err: git.ErrRepositoryAlreadyExists => local repo is already cloned
	// err: nil => local repo is newly cloned
	return repo, err
}

func pull(repo *git.Repository) error {
	wt, err := repo.Worktree()
	if err != nil {
		panic(err)
	}

	err = wt.Pull(&git.PullOptions{
		Progress: os.Stdout,
		// Depth:    1,
	})

	// err: git.NoErrAlreadyUpToDate => local repo is up to date
	// err: nil => new pushs found and pulled to local repo
	return err
}

func getUpdatedFiles(oldCommit, newCommit *object.Commit) map[string][]string {
	patch, err := oldCommit.Patch(newCommit)
	if err != nil {
		log.Fatal(err)
	}

	// modified: update database
	// deleted: delete data from database
	// added: insert to database
	var statusMap = make(map[string][]string)

	for _, filePatch := range patch.FilePatches() {
		from, to := filePatch.Files()
		if from != nil && to != nil { // modified
			if _, ok := statusMap[statusModified]; !ok {
				statusMap[statusModified] = []string{}
			}
			statusMap[statusModified] = append(statusMap[statusModified], to.Path())
		} else if from != nil { // deleted
			if _, ok := statusMap[statusDeleted]; !ok {
				statusMap[statusDeleted] = []string{}
			}
			statusMap[statusDeleted] = append(statusMap[statusDeleted], from.Path())
		} else if to != nil { // added
			if _, ok := statusMap[statusAdded]; !ok {
				statusMap[statusAdded] = []string{}
			}
			statusMap[statusAdded] = append(statusMap[statusAdded], to.Path())
		}
	}
	return statusMap
}

func getCurrentHash(repo *git.Repository) (*plumbing.Hash, error) {
	hash, err := repo.ResolveRevision(plumbing.Revision("HEAD"))
	if err != nil {
		return nil, err
	}
	return hash, nil
}

// TODO: make it return a map with status (modified, deleted, added) as key, list of CVE JSON path as value
func localCveSummary() map[string][]string {
	var cveFiles = make(map[string][]string)
	repo, err := cloneRepo(localRepoPath())

	if err == git.ErrRepositoryAlreadyExists {
		fmt.Println("Repository already exists, pulling from remote...")
		oldHash, err := getCurrentHash(repo)
		if err != nil {
			log.Fatal(err)
		}

		err = pull(repo)
		if err == nil { // new commits found
			newHash, err := getCurrentHash(repo)
			if err != nil {
				log.Fatal(err)
			}
			oldCommit, _ := repo.CommitObject(*oldHash)
			newCommit, _ := repo.CommitObject(*newHash)
			// cveFiles = getUpdatedFiles(oldCommit, newCommit)
			// cveFiles = filterFiles(cveFiles, "", filenamePattern)

			cveFiles = getUpdatedFiles(oldCommit, newCommit)
			cveFiles[statusModified] = filterFiles(cveFiles[statusModified], "", filenamePattern)
			cveFiles[statusDeleted] = filterFiles(cveFiles[statusDeleted], "", filenamePattern)
			cveFiles[statusAdded] = filterFiles(cveFiles[statusAdded], "", filenamePattern)
		} else if err == git.NoErrAlreadyUpToDate { // up-to-date
			fmt.Println(err)
		} else { // other error
			log.Fatal(err)
		}
	} else { // fresh clone
		// cveFiles = filterFiles(nil, localRepoPath(), filenamePattern)
		cveFiles[statusAdded] = filterFiles(nil, localRepoPath(), filenamePattern)
	}

	return cveFiles
}
