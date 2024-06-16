package services

import (
	"context"
	"fmt"
	"log"

	"go.mongodb.org/mongo-driver/bson"

	model "cve-dict/model"

	db "cve-dict/services/database"
)

func QueryByCveId(dbConfig model.DbConfig, cveId string) []model.Cve {
	client := db.Connect(db.ConstructUri(dbConfig.DbHost, dbConfig.DbPort))
	defer db.Disconnect(client)

	cursor := db.Query(client, dbConfig.Database, dbConfig.Collection, bson.D{{Key: "cveId", Value: cveId}})

	var cves []model.Cve
	if err := cursor.All(context.TODO(), &cves); err != nil {
		log.Fatal(err)
	}

	for _, cve := range cves {
		fmt.Printf("%+v\n", cve)
	}

	return nil
}
