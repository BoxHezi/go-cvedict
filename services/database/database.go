package database

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	model "cve-dict/model"
)

func ConstructUri(host string, port uint32) string {
	return fmt.Sprintf("mongodb://%s:%d", host, port)
}

func Connect(uri string) *mongo.Client {
	if uri == "" {
		panic("Please provide MongoDB connection URI")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatal(err)
	}

	return client
}

func TestConnection(client *mongo.Client) error {
	err := client.Ping(context.TODO(), nil)
	if err != nil {
		return err
	}
	return nil
}

func InsertOne(client *mongo.Client, database, collection string, cve model.Cve) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	col := client.Database(database).Collection(collection)
	result, err := col.InsertOne(ctx, cve)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[INFO] Database: %s, Insert %s successfully, ID: %s\n", database, cve.Id, result.InsertedID)
}

func InsertMany(client *mongo.Client, database, collection string, cves []model.Cve) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	var bDocs []interface{} // convert []model.Cve to []interface{}
	for _, c := range cves {
		bDocs = append(bDocs, c)
	}

	col := client.Database(database).Collection(collection)
	result, err := col.InsertMany(ctx, bDocs)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[INFO] Database: %s, Insert %d documents to Collection: %s\n", database, len(result.InsertedIDs), collection)
}

func UpdateOne(client *mongo.Client, database, collection, cveId string, cve model.Cve) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	col := client.Database(database).Collection(collection)
	filter := bson.D{{Key: "id", Value: cveId}}
	update := bson.D{{Key: "$set", Value: cve}}
	_, err := col.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[INFO] Database: %s, Update %s successfully\n", database, cveId)
}

func DeleteOne(client *mongo.Client, database, collection, cveId string) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	col := client.Database(database).Collection(collection)
	filter := bson.D{{Key: "id", Value: cveId}}
	_, err := col.DeleteOne(ctx, filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[INFO] Database: %s, Delete %s successfully\n", database, cveId)
}

func Query(client *mongo.Client, database, collection string, filter bson.D) *mongo.Cursor {
	ctx, cancel := context.WithTimeout(context.TODO(), 30*time.Second)
	defer cancel()

	cursor, err := client.Database(database).Collection(collection).Find(ctx, filter)
	if err != nil {
		log.Fatal(err)
	}

	return cursor
}

func Disconnect(client *mongo.Client) {
	client.Disconnect(context.TODO())
}
