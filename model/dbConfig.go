package model

type DbConfig struct {
	DbHost     string
	DbPort     uint32
	Database   string
	Collection string
}

func CreateDbConfig(flags RootFlag) *DbConfig {
	dbConfig := new(DbConfig)
	dbConfig.SetDbHost(*flags.GetAddressP())
	dbConfig.SetDbPort(*flags.GetPortP())
	dbConfig.SetDatabase(*flags.GetDatabaseP())
	dbConfig.SetCollection(*flags.GetCollectionP())
	return dbConfig
}

func (d *DbConfig) SetDbHost(host string) {
	d.DbHost = host
}

func (d *DbConfig) SetDbPort(port uint32) {
	d.DbPort = port
}

func (d *DbConfig) SetDatabase(database string) {
	d.Database = database
}

func (d *DbConfig) SetCollection(collection string) {
	d.Collection = collection
}
