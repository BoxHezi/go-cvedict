# go-cvedict

<!-- ### TODO:

- [x] Add flag to indicate clone or pull
  - [x] If clone, parse all CVEs and insert to database
  - [x] If pull, upsert data
- [ ] Add argparser for command line usage
- [ ] Add webserver function to act as an API
- [ ] Add progress bar to indicate progress -->

A CVE database can be deployed locally written in Go.

## Prerequisite

- A mongodb that can be accessed.

## Deployment

1. Clone the repo
2. run `cd go-cvedict && go mod download`
3. Use `go run main.go help` to check if there are any error

```bash
Local CVE Dictionary

Usage:
  cvedict [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  fetch       CVE dict
  help        Help about any command
  search      CVE dict
  server      Start server
  update      Update CVE dict

Flags:
  -a, --address string      database address (default "127.0.0.1")
  -c, --collection string   collection name (default "cve")
  -d, --database string     database name (default "nvd")
  -h, --help                help for cvedict
  -n, --notifer string      notifier url
  -p, --port uint32         database port (default 27017)

Use "cvedict [command] --help" for more information about a command.
```

### Fetch CVE data from NIST NVD

Use the command `go run main.go fetch -a <mongodb address> -p <mongodb port> -d <database name> -c <collection name>`, where default values for these arguments are:

- mongodb address - 127.0.0.1
- mongodb port - 27017
- database name - nvd
- collection name - cve

### RESTful API

Simple RESTful API are provided to update database and query CVE data.
Using the command `go run main.go server` to start the RESTful API backend. It uses port 8080 by default.

#### Update

`curl http://localhost:8080/update`

#### Query CVE

There are three options to search for CVE(s):

1. By using CVE id - `curl http://localhost:8080/cve/id/<cveid>`
2. By using CVE published year - `curl http://localhost:8080/cve/year/<year>`
3. General search - `curl http://localhost:8080/search?<filter>`

When doing general search, the filter parameter value is the same as to access the data in JSON format. For example, if to filter `gitlab` from descriptions, the filter will be `descriptions.value=gitlab`. For multiple filters, simple add `&<filter>`. For example, to filter both `gitlab` and `password`, the filter will be `descriptions.value=gitlab&descriptions.value=password`.

TODO:

- [ ] - add regex support for filter
- [ ] - add OR option if multiple filters are passed in
