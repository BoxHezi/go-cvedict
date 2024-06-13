package services

import (
	"go.mongodb.org/mongo-driver/mongo"

	model "cve-dict/model"
	db "cve-dict/services/database"
)

func UpdateDatabase(client *mongo.Client, database, collection string, addedCves []model.Cve, modifiedCves []model.Cve, deletedCves []model.Cve) {
	if len(addedCves) > 0 {
		db.InsertMany(*client, database, collection, addedCves)
	}

	for _, c := range modifiedCves {
		db.UpdateOne(*client, database, collection, c.Id, c)
	}

	for _, c := range deletedCves {
		db.DeleteOne(*client, database, collection, c.Id)
	}
}
