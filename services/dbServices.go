package services

import (
	"context"
	"log"
	"sync"

	"go.mongodb.org/mongo-driver/bson"

	model "cvedict/model"
	db "cvedict/services/database"
)

func (sc ServicesConfig) doUpdateDatabase(addCves, modifiedCves, deletedCves []model.Cve, wg *sync.WaitGroup) {
	if wg != nil {
		defer wg.Done()
	}

	client := db.Connect(db.ConstructUri(sc.dbConfig.DbHost, sc.dbConfig.DbPort))
	defer db.Disconnect(client)

	if len(addCves) > 0 {
		db.InsertMany(client, sc.dbConfig.Database, sc.dbConfig.Collection, addCves)
	}

	for _, c := range modifiedCves {
		db.UpdateOne(client, sc.dbConfig.Database, sc.dbConfig.Collection, c.Id, c)
	}

	for _, c := range deletedCves {
		db.DeleteOne(client, sc.dbConfig.Database, sc.dbConfig.Collection, c.Id)
	}
}

func (sc ServicesConfig) doQueryCves(query bson.D) []model.Cve {
	client := db.Connect(db.ConstructUri(sc.dbConfig.DbHost, sc.dbConfig.DbPort))
	defer db.Disconnect(client)

	cursor := db.Query(client, sc.dbConfig.Database, sc.dbConfig.Collection, query)

	var cves []model.Cve
	if err := cursor.All(context.TODO(), &cves); err != nil {
		log.Fatal(err)
	}
	return cves
}

func (sc ServicesConfig) doRenameDbCollection(newName string) {
	client := db.Connect(db.ConstructUri(sc.dbConfig.DbHost, sc.dbConfig.DbPort))
	defer db.Disconnect(client)

	db.RenameCollection(client, sc.dbConfig.Database, sc.dbConfig.Collection, newName)
}

func (sc ServicesConfig) doDropCollection(collection string) {
	client := db.Connect(db.ConstructUri(sc.dbConfig.DbHost, sc.dbConfig.DbPort))
	defer db.Disconnect(client)

	db.DropCollection(client, sc.dbConfig.Database, collection)
}
