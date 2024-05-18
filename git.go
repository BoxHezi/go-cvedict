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
		Depth:    1,
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
	})

	// err: git.NoErrAlreadyUpToDate => local repo is up to date
	// err: nil => new pushs found and pulled to local repo
	return err
}

func getUpdatedFiles(oldCommit, newCommit *object.Commit) []string {
	patch, err := oldCommit.Patch(newCommit)
	if err != nil {
		log.Fatal(err)
	}
	// TODO: separate modified, deleted, added files
	// modified: update database
	// deleted: delete data from database
	// added: insert to database
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

// localCves retrieves a list of CVE file paths based on changes in the local repository.
//
// No parameters.
// Returns a slice of strings representing the file paths.
func localCves() []string {
	var cveFiles []string = []string{}
	repo, err := cloneRepo(localRepoPath())

	if err == git.ErrRepositoryAlreadyExists {
		fmt.Println("Repository already exists, pulling from remote...")
		oldHash, err := getCurrentHash(repo)
		if err != nil {
			log.Fatal(err)
		}

		err = pull(repo)
		if err != git.NoErrAlreadyUpToDate { // new commits found
			newHash, err := getCurrentHash(repo)
			if err != nil {
				log.Fatal(err)
			}
			oldCommit, _ := repo.CommitObject(*oldHash)
			newCommit, _ := repo.CommitObject(*newHash)
			cveFiles = getUpdatedFiles(oldCommit, newCommit)
			cveFiles = filterFiles(cveFiles, "", filenamePattern)
		} else { // up-to-date
			fmt.Println(git.NoErrAlreadyUpToDate)
		}
	} else { // fresh clone
		cveFiles = filterFiles(nil, localRepoPath(), filenamePattern)
	}

	return cveFiles
}
