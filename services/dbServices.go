package services

import (
	"context"
	"log"

	"go.mongodb.org/mongo-driver/bson"

	model "cvedict/model"
	db "cvedict/services/database"
)

func QueryCves(sc ServicesConfig, query bson.D) []model.Cve {
	client := db.Connect(db.ConstructUri(sc.dbConfig.DbHost, sc.dbConfig.DbPort))
	defer db.Disconnect(client)

	cursor := db.Query(client, sc.dbConfig.Database, sc.dbConfig.Collection, query)

	var cves []model.Cve
	if err := cursor.All(context.TODO(), &cves); err != nil {
		log.Fatal(err)
	}
	return cves
}
