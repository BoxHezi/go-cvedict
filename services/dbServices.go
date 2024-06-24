package services

import (
	"context"
	"log"

	"go.mongodb.org/mongo-driver/bson"

	model "cvedict/model"
	db "cvedict/services/database"
)

func QueryCves(dbConfig model.DbConfig, query bson.D) []model.Cve {
	client := db.Connect(db.ConstructUri(dbConfig.DbHost, dbConfig.DbPort))
	defer db.Disconnect(client)

	cursor := db.Query(client, dbConfig.Database, dbConfig.Collection, query)

	var cves []model.Cve
	if err := cursor.All(context.TODO(), &cves); err != nil {
		log.Fatal(err)
	}
	return cves
}
