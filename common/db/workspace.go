package db

import (
	"GADS/common/models"
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func AddWorkspace(workspace *models.Workspace) error {
	collection := mongoClient.Database("gads").Collection("workspaces")
	result, err := collection.InsertOne(mongoClientCtx, workspace)
	if err != nil {
		return err
	}
	workspace.ID = result.InsertedID.(primitive.ObjectID).Hex()
	return nil
}

func UpdateWorkspace(workspace *models.Workspace) error {
	collection := mongoClient.Database("gads").Collection("workspaces")

	objectID, err := primitive.ObjectIDFromHex(workspace.ID)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": objectID}
	update := bson.M{
		"$set": bson.M{
			"name":        workspace.Name,
			"description": workspace.Description,
		},
	}
	_, err = collection.UpdateOne(mongoClientCtx, filter, update)
	if err != nil {
		return err
	}
	return nil
}

func DeleteWorkspace(id string) error {
	collection := mongoClient.Database("gads").Collection("workspaces")

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	filter := bson.M{"_id": objectID}
	_, err = collection.DeleteOne(mongoClientCtx, filter)
	if err != nil {
		return err
	}
	return nil
}

func GetWorkspaces() []models.Workspace {
	var workspaces []models.Workspace
	collection := mongoClient.Database("gads").Collection("workspaces")

	cursor, err := collection.Find(mongoClientCtx, bson.M{})
	if err != nil {
		return workspaces
	}
	defer cursor.Close(mongoClientCtx)

	cursor.All(mongoClientCtx, &workspaces)
	return workspaces
}

func WorkspaceHasDevices(id string) bool {
	collection := mongoClient.Database("gads").Collection("new_devices")
	filter := bson.M{"workspace_id": id}
	count, err := collection.CountDocuments(mongoClientCtx, filter)
	if err != nil {
		return false
	}
	return count > 0
}

func WorkspaceHasUsers(id string) bool {
	collection := mongoClient.Database("gads").Collection("users")
	filter := bson.M{"workspace_ids": id}
	count, err := collection.CountDocuments(mongoClientCtx, filter)
	if err != nil {
		return false
	}
	return count > 0
}

func GetWorkspaceByID(id string) (models.Workspace, error) {
	var workspace models.Workspace
	collection := mongoClient.Database("gads").Collection("workspaces")
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return models.Workspace{}, err
	}

	filter := bson.M{"_id": objectID}

	err = collection.FindOne(context.TODO(), filter).Decode(&workspace)
	if err != nil {
		return models.Workspace{}, err
	}
	return workspace, nil
}

func GetWorkspaceByName(name string) (models.Workspace, error) {
	var workspace models.Workspace
	collection := mongoClient.Database("gads").Collection("workspaces")
	filter := bson.M{"name": name}

	err := collection.FindOne(context.TODO(), filter).Decode(&workspace)
	if err != nil {
		return models.Workspace{}, err
	}
	return workspace, nil
}

func GetDefaultWorkspace() (models.Workspace, error) {
	var workspace models.Workspace
	collection := mongoClient.Database("gads").Collection("workspaces")
	filter := bson.M{"is_default": true}

	err := collection.FindOne(context.TODO(), filter).Decode(&workspace)
	if err != nil {
		return models.Workspace{}, err
	}
	return workspace, nil
}

func GetWorkspacesPaginated(page, limit int, search string) ([]models.Workspace, int64) {
	var workspaces []models.Workspace
	collection := mongoClient.Database("gads").Collection("workspaces")

	// Calculate the number of documents to skip
	skip := (page - 1) * limit

	filter := bson.M{}
	if search != "" {
		filter["name"] = bson.M{"$regex": search, "$options": "i"} // Case-insensitive search
	}

	cursor, err := collection.Find(mongoClientCtx, filter, options.Find().SetSkip(int64(skip)).SetLimit(int64(limit)))
	if err != nil {
		return workspaces, 0
	}
	defer cursor.Close(mongoClientCtx)

	for cursor.Next(mongoClientCtx) {
		var workspace models.Workspace
		if err := cursor.Decode(&workspace); err != nil {
			continue
		}
		workspaces = append(workspaces, workspace)
	}

	// Get total count of workspaces
	count, err := collection.CountDocuments(mongoClientCtx, filter)
	if err != nil {
		return workspaces, 0
	}

	return workspaces, count
}

func GetUserWorkspacesPaginated(username string, page, limit int, search string) ([]models.Workspace, int64) {
	var workspaces []models.Workspace
	collection := mongoClient.Database("gads").Collection("workspaces")

	// Calculate skip for pagination
	skip := (page - 1) * limit

	// Get user's workspace IDs from users collection
	userCollection := mongoClient.Database("gads").Collection("users")
	var user models.User
	err := userCollection.FindOne(mongoClientCtx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		return workspaces, 0
	}

	// Build filter for workspaces
	filter := bson.M{"_id": bson.M{"$in": user.WorkspaceIDs}}
	if search != "" {
		filter["name"] = bson.M{"$regex": search, "$options": "i"}
	}

	// Get workspaces with pagination
	cursor, err := collection.Find(mongoClientCtx, filter,
		options.Find().
			SetSkip(int64(skip)).
			SetLimit(int64(limit)))
	if err != nil {
		return workspaces, 0
	}
	defer cursor.Close(mongoClientCtx)

	for cursor.Next(mongoClientCtx) {
		var workspace models.Workspace
		if err := cursor.Decode(&workspace); err != nil {
			continue
		}
		workspaces = append(workspaces, workspace)
	}

	// Get total count
	count, err := collection.CountDocuments(mongoClientCtx, filter)
	if err != nil {
		return workspaces, 0
	}

	return workspaces, count
}
