package git

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

const (
	gitRepoUrl         = "https://github.com/fkie-cad/nvd-json-data-feeds.git"
	localDirSuffix     = "/.config/cvedb/nvdcve"
	cveFilenamePattern = "CVE-*.json"

	Modified = "modified"
	Deleted  = "deleted"
	Added    = "added"
)

func filterFiles(files []string, path string, pattern string) []string {
	if pattern == "" {
		log.Fatal("Please provide pattern")
	}

	var filteredFiles []string = []string{}
	if path == "" {
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
	} else if files == nil {
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
	}
	return filteredFiles
}

func localRepoPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	return home + localDirSuffix
}

func cloneRepo(localPath string) (*git.Repository, error) {
	fmt.Printf("Cloning repo to %s\n", localPath)
	repo, err := git.PlainClone(localPath, false, &git.CloneOptions{
		URL:      gitRepoUrl,
		Progress: os.Stdout,
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

func getUpdatedFiles(oldCommit, newCommit *object.Commit) map[string][]string {
	patch, err := oldCommit.Patch(newCommit)
	if err != nil {
		log.Fatal(err)
	}

	var statusMap = make(map[string][]string)

	for _, filePatch := range patch.FilePatches() {
		from, to := filePatch.Files()
		if from != nil && to != nil { // modified
			if _, ok := statusMap[Modified]; !ok {
				statusMap[Modified] = []string{}
			}
			statusMap[Modified] = append(statusMap[Modified], to.Path())
		} else if from != nil { // deleted
			if _, ok := statusMap[Deleted]; !ok {
				statusMap[Deleted] = []string{}
			}
			statusMap[Deleted] = append(statusMap[Deleted], from.Path())
		} else if to != nil { // added
			if _, ok := statusMap[Added]; !ok {
				statusMap[Added] = []string{}
			}
			statusMap[Added] = append(statusMap[Added], to.Path())
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

// InitLocalRepo initializes a local repository and returns a map of updated files.
//
// This function clones a repository if it already exists or pulls changes from the remote repository.
// It then retrieves the current hash of the repository and compares it with the previous hash to determine the updated files.
// The updated files are filtered based on a filename pattern.
// The function returns a map where the keys represent the status of the files (modified, deleted, or added)
// and the values are slices of file paths.
//
// Returns:
// - map[string][]string: A map of updated files, where the keys represent the status of the files and the values are slices of file paths.
func InitLocalRepo() map[string][]string {
	var cveFiles = make(map[string][]string)
	repo, err := cloneRepo(localRepoPath())

	if err == git.ErrRepositoryAlreadyExists {
		fmt.Println("Repository already exists, pulling from remote...")
		oldHash, err := getCurrentHash(repo)
		if err != nil {
			log.Fatal(err)
		}

		err = pull(repo)
		if err == nil { // new commits found and pulled to local repo
			newHash, err := getCurrentHash(repo)
			if err != nil {
				log.Fatal(err)
			}
			oldCommit, _ := repo.CommitObject(*oldHash)
			newCommit, _ := repo.CommitObject(*newHash)

			cveFiles = getUpdatedFiles(oldCommit, newCommit)
			cveFiles[Modified] = filterFiles(cveFiles[Modified], "", cveFilenamePattern)
			cveFiles[Deleted] = filterFiles(cveFiles[Deleted], "", cveFilenamePattern)
			cveFiles[Added] = filterFiles(cveFiles[Added], "", cveFilenamePattern)
		} else if err == git.NoErrAlreadyUpToDate { // up-to-date
			fmt.Println(err)
		} else { // other error
			log.Fatal(err)
		}
	} else { // fresh clone
		cveFiles[Added] = filterFiles(nil, localRepoPath(), cveFilenamePattern)
	}

	return cveFiles
}
