package services

import (
	"context"
	"log"

	"go.mongodb.org/mongo-driver/bson"

	model "cve-dict/model"

	db "cve-dict/services/database"
)

// func QueryByCveId(dbConfig model.DbConfig, cveId string) []model.Cve {
// 	client := dbConnect(dbConfig)
// 	defer db.Disconnect(client)

// 	cursor := db.Query(client, dbConfig.Database, dbConfig.Collection, bson.D{{Key: "id", Value: cveId}})

// 	var cves []model.Cve
// 	if err := cursor.All(context.TODO(), &cves); err != nil {
// 		log.Fatal(err)
// 	}

// 	return cves
// }

// func QueryByYear(dbConfig model.DbConfig, year string) []model.Cve {
// 	client := dbConnect(dbConfig)
// 	defer db.Disconnect(client)

// 	cursor := db.Query(client, dbConfig.Database, dbConfig.Collection, bson.D{{Key: "id", Value: bson.D{
// 		{Key: "$regex", Value: fmt.Sprintf("CVE-%s-*", year)},
// 	}}})

// 	var cves []model.Cve
// 	if err := cursor.All(context.TODO(), &cves); err != nil {
// 		log.Fatal(err)
// 	}

// 	return cves
// }

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
