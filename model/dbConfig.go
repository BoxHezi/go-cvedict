package model

type DbConfig struct {
	DbHost     string
	DbPort     uint32
	Database   string
	Collection string
}

func CreateDbConfig(flags RootFlag) *DbConfig {
	dbConfig := new(DbConfig)
	dbConfig.setupDbConfig(flags)
	return dbConfig
}

func (d *DbConfig) setupDbConfig(flags RootFlag) {
	d.SetDbHost(*flags.GetAddressP())
	d.SetDbPort(*flags.GetPortP())
	d.SetDatabase(*flags.GetDatabaseP())
	d.SetCollection(*flags.GetCollectionP())
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
