package database

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func Connect(uri string) *mongo.Client {
	if uri == "" {
		// panic("Please provide MongoDB connection URI")
		uri = "mongodb://localhost:27100"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatal(err)
	}

	return client
}

func InsertOne(client mongo.Client, database, collection string, document interface{}) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	col := client.Database(database).Collection(collection)
	result, err := col.InsertOne(ctx, document)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Inserted document with ID:", result.InsertedID)
}

func InsertMany(client mongo.Client, database, collection string, documents []interface{}) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	col := client.Database(database).Collection(collection)

	result, err := col.InsertMany(ctx, documents)
	if err != nil {
		fmt.Println("ERROR DURING InsertMany")
		log.Fatal(err)
	}
	// fmt.Println(result.InsertedIDs...)
	fmt.Printf("[INFO] Database: %s, Insert %d documents to Collection: %s\n", database, len(result.InsertedIDs), collection)
}

func UpdateOne(client mongo.Client, database, collection, cveId string, document interface{}) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	col := client.Database(database).Collection(collection)
	filter := bson.D{{Key: "id", Value: cveId}}
	_, err := col.UpdateOne(ctx, filter, document)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[INFO] Database: %s, Update %s successfully\n", database, cveId)

	// fmt.Printf("Update MatchedCount: %d, Update ModifiedCount: %d\n", result.MatchedCount, result.ModifiedCount)
	// fmt.Printf("UpsertedCount: %d, UpsertedID: %v\n", result.UpsertedCount, result.UpsertedID)
}

func DeleteOne(client mongo.Client, database, collection, cveId string) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	col := client.Database(database).Collection(collection)
	filter := bson.D{{Key: "id", Value: cveId}}
	_, err := col.DeleteOne(ctx, filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[INFO] Database: %s, Delete %s successfully\n", database, cveId)
	// fmt.Printf("DeletedCount: %d, DeletedID: %v\n", result.DeletedCount, cveId)
}

func Query(client mongo.Client, database, collection string, filter bson.D) *mongo.Cursor {
	ctx, cancel := context.WithTimeout(context.TODO(), 30*time.Second)
	defer cancel()

	cursor, err := client.Database(database).Collection(collection).Find(ctx, filter)
	if err != nil {
		log.Fatal(err)
	}

	return cursor
}

func Disconnect(client mongo.Client) {
	client.Disconnect(context.TODO())
}
