package model

type RootFlag struct {
	address    string
	port       uint32
	database   string
	collection string
}

func (c *RootFlag) GetAddressP() *string {
	return &c.address
}

func (c *RootFlag) GetPortP() *uint32 {
	return &c.port
}

func (c *RootFlag) GetDatabaseP() *string {
	return &c.database
}

func (c *RootFlag) GetCollectionP() *string {
	return &c.collection
}
