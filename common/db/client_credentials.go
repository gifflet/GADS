/*
 * This file is part of GADS.
 *
 * Copyright (c) 2022-2025 Nikola Shabanov
 *
 * This source code is licensed under the GNU Affero General Public License v3.0.
 * You may obtain a copy of the license at https://www.gnu.org/licenses/agpl-3.0.html
 */

package db

import (
	"GADS/common/models"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// CreateClientCredential creates a new client credential
func (m *MongoStore) CreateClientCredential(credential *models.ClientCredential) error {
	coll := m.GetCollection("client_credentials")
	credential.CreatedAt = time.Now()
	credential.UpdatedAt = time.Now()

	result, err := InsertDocumentWithResult[models.ClientCredential](m.Ctx, coll, *credential)
	if err != nil {
		return err
	}
	credential.ID = result.InsertedID.(primitive.ObjectID).Hex()
	return nil
}

// GetClientCredentialByClientID retrieves a client credential by client_id
func (m *MongoStore) GetClientCredentialByClientID(clientID string) (models.ClientCredential, error) {
	coll := m.GetCollection("client_credentials")
	filter := bson.M{"client_id": clientID, "is_active": true}
	return GetDocument[models.ClientCredential](m.Ctx, coll, filter)
}

// GetClientCredentialsByUserID retrieves all client credentials for a user
func (m *MongoStore) GetClientCredentialsByUserID(userID string) ([]models.ClientCredential, error) {
	coll := m.GetCollection("client_credentials")
	filter := bson.M{"user_id": userID}
	return GetDocuments[models.ClientCredential](m.Ctx, coll, filter)
}

// GetClientCredentialsByTenant retrieves all client credentials for a tenant
func (m *MongoStore) GetClientCredentialsByTenant(tenant string) ([]models.ClientCredential, error) {
	coll := m.GetCollection("client_credentials")
	filter := bson.M{"tenant": tenant}
	return GetDocuments[models.ClientCredential](m.Ctx, coll, filter)
}

// UpdateClientCredential updates a client credential
func (m *MongoStore) UpdateClientCredential(credential *models.ClientCredential) error {
	coll := m.GetCollection("client_credentials")
	objectID, err := primitive.ObjectIDFromHex(credential.ID)
	if err != nil {
		return err
	}

	credential.UpdatedAt = time.Now()
	filter := bson.M{"_id": objectID}
	update := bson.M{
		"name":        credential.Name,
		"description": credential.Description,
		"is_active":   credential.IsActive,
		"updated_at":  credential.UpdatedAt,
	}
	return PartialDocumentUpdate(m.Ctx, coll, filter, update)
}

// UpdateClientCredentialLastUsed updates the last_used_at timestamp
func (m *MongoStore) UpdateClientCredentialLastUsed(clientID string) error {
	coll := m.GetCollection("client_credentials")
	filter := bson.M{"client_id": clientID}
	now := time.Now()
	update := bson.M{
		"last_used_at": now,
		"updated_at":   now,
	}
	return PartialDocumentUpdate(m.Ctx, coll, filter, update)
}

// DeleteClientCredential deletes a client credential
func (m *MongoStore) DeleteClientCredential(id string) error {
	coll := m.GetCollection("client_credentials")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}
	filter := bson.M{"_id": objectID}
	return DeleteDocument(m.Ctx, coll, filter)
}

// DisableClientCredential sets is_active to false instead of deleting
func (m *MongoStore) DisableClientCredential(id string) error {
	coll := m.GetCollection("client_credentials")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": objectID}
	update := bson.M{
		"is_active":  false,
		"updated_at": time.Now(),
	}
	return PartialDocumentUpdate(m.Ctx, coll, filter, update)
}

// InitClientCredentialsCollection initializes the client_credentials collection with indexes
func (m *MongoStore) InitClientCredentialsCollection() error {
	collectionName := "client_credentials"

	// Check if collection exists
	exists, err := m.CheckCollectionExists(collectionName)
	if err != nil {
		return err
	}

	// Create collection if it doesn't exist
	if !exists {
		if err := m.CreateCollection(collectionName, nil); err != nil {
			return err
		}
	}

	// Create indexes for performance
	indexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "client_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "user_id", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "tenant", Value: 1}},
		},
		{
			Keys: bson.D{
				{Key: "tenant", Value: 1},
				{Key: "user_id", Value: 1},
			},
		},
	}

	for _, index := range indexes {
		if err := m.AddCollectionIndex(collectionName, index); err != nil {
			// Ignore duplicate key errors (index already exists)
			if !mongo.IsDuplicateKeyError(err) {
				return err
			}
		}
	}

	return nil
}
