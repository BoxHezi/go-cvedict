package model

type CmdFlags struct {
	address    string
	port       uint32
	database   string
	collection string
}

func (c *CmdFlags) GetAddressP() *string {
	return &c.address
}

func (c *CmdFlags) GetPortP() *uint32 {
	return &c.port
}

func (c *CmdFlags) GetDatabaseP() *string {
	return &c.database
}

func (c *CmdFlags) GetCollectionP() *string {
	return &c.collection
}
