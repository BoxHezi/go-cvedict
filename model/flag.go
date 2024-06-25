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
