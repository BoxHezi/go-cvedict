clean:
	rm -f ./cvedict

linux:
	GOOS=linux GOARCH=amd64 go build -o cvedict -v

windows:
	GOOS=windows GOARCH=amd64 go build -o cvedict.exe -v

macos:
	GOOS=darwin GOARCH=amd64 go build -o cvedict -v
