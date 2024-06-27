package model

type RootFlag struct {
	address    string
	port       uint32
	database   string
	collection string

	notifierUrl string
}

func (f *RootFlag) GetAddressP() *string {
	return &f.address
}

func (f *RootFlag) GetPortP() *uint32 {
	return &f.port
}

func (f *RootFlag) GetDatabaseP() *string {
	return &f.database
}

func (f *RootFlag) GetCollectionP() *string {
	return &f.collection
}

func (f *RootFlag) GetNotifierUrlP() *string {
	return &f.notifierUrl
}

type ServerFlag struct {
	port uint32
}

func (f *ServerFlag) GetPortP() *uint32 {
	return &f.port
}

type SearchFlag struct {
	id   string
	year string
	desc string
	cvss float32 // filter cvss score greater than or equal to value passed in
}

// check if there is any value be set for seaarch flags
func (f *SearchFlag) IsEmpty() bool {
	return f.id == "" && f.year == "" && f.desc == ""
}

func (f *SearchFlag) GetIdP() *string {
	return &f.id
}

func (f *SearchFlag) GetYearP() *string {
	return &f.year
}

func (f *SearchFlag) GetDescP() *string {
	return &f.desc
}

func (f *SearchFlag) GetCvssP() *float32 {
	return &f.cvss
}
