package clientcredentials

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// ClientCredentials represents OAuth2 client credentials configuration
type ClientCredentials struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	ClientID     string             `bson:"client_id" json:"client_id"`
	ClientSecret string             `bson:"client_secret" json:"-"` // Never return secret in JSON
	Name         string             `bson:"name" json:"name"`
	Description  string             `bson:"description" json:"description"`
	Scopes       []string           `bson:"scopes" json:"scopes"`
	IsActive     bool               `bson:"is_active" json:"is_active"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time          `bson:"updated_at" json:"updated_at"`
	CreatedBy    string             `bson:"created_by" json:"created_by"`
}

// ClientCredentialsService manages OAuth2 client credentials
type ClientCredentialsService struct {
	collection *mongo.Collection
	jwtSecret  []byte
	crypto     *CryptoService
}

// NewClientCredentialsService creates a new client credentials service
func NewClientCredentialsService(db *mongo.Database, jwtSecret []byte) *ClientCredentialsService {
	return &ClientCredentialsService{
		collection: db.Collection("client_credentials"),
		jwtSecret:  jwtSecret,
		crypto:     NewCryptoService(),
	}
}

// CreateClientCredentials creates new client credentials
func (s *ClientCredentialsService) CreateClientCredentials(ctx context.Context, name, description string, scopes []string, createdBy string) (*ClientCredentials, string, error) {
	clientID, err := s.crypto.GenerateClientID()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate client ID: %w", err)
	}

	clientSecret, err := s.crypto.GenerateClientSecret()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate client secret: %w", err)
	}

	hashedSecret, err := s.crypto.HashSecret(clientSecret)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash client secret: %w", err)
	}

	credentials := &ClientCredentials{
		ID:           primitive.NewObjectID(),
		ClientID:     clientID,
		ClientSecret: hashedSecret,
		Name:         name,
		Description:  description,
		Scopes:       scopes,
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		CreatedBy:    createdBy,
	}

	_, err = s.collection.InsertOne(ctx, credentials)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create client credentials: %w", err)
	}

	// Return credentials without hashed secret and the plain secret separately
	credentials.ClientSecret = ""
	return credentials, clientSecret, nil
}

// AuthenticateClient validates client credentials and returns access token
func (s *ClientCredentialsService) AuthenticateClient(ctx context.Context, clientID, clientSecret string) (string, error) {
	var credentials ClientCredentials
	err := s.collection.FindOne(ctx, bson.M{
		"client_id": clientID,
		"is_active": true,
	}).Decode(&credentials)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return "", fmt.Errorf("invalid client credentials")
		}
		return "", fmt.Errorf("failed to find client: %w", err)
	}

	if !s.crypto.ValidateSecret(clientSecret, credentials.ClientSecret) {
		return "", fmt.Errorf("invalid client credentials")
	}

	token, err := s.generateAccessToken(credentials.ClientID, credentials.Scopes)
	if err != nil {
		return "", fmt.Errorf("failed to generate access token: %w", err)
	}

	return token, nil
}

// GetClientCredentials retrieves client credentials by ID
func (s *ClientCredentialsService) GetClientCredentials(ctx context.Context, id primitive.ObjectID) (*ClientCredentials, error) {
	var credentials ClientCredentials
	err := s.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to get client credentials: %w", err)
	}

	credentials.ClientSecret = "" // Never return secret
	return &credentials, nil
}

// ListClientCredentials retrieves all client credentials
func (s *ClientCredentialsService) ListClientCredentials(ctx context.Context) ([]*ClientCredentials, error) {
	cursor, err := s.collection.Find(ctx, bson.M{})
	if err != nil {
		return nil, fmt.Errorf("failed to list client credentials: %w", err)
	}
	defer cursor.Close(ctx)

	var credentialsList []*ClientCredentials
	for cursor.Next(ctx) {
		var credentials ClientCredentials
		if err := cursor.Decode(&credentials); err != nil {
			return nil, fmt.Errorf("failed to decode client credentials: %w", err)
		}
		credentials.ClientSecret = "" // Never return secret
		credentialsList = append(credentialsList, &credentials)
	}

	return credentialsList, nil
}

// UpdateClientCredentials updates existing client credentials
func (s *ClientCredentialsService) UpdateClientCredentials(ctx context.Context, id primitive.ObjectID, name, description string, scopes []string, isActive bool) error {
	update := bson.M{
		"$set": bson.M{
			"name":        name,
			"description": description,
			"scopes":      scopes,
			"is_active":   isActive,
			"updated_at":  time.Now(),
		},
	}

	result, err := s.collection.UpdateOne(ctx, bson.M{"_id": id}, update)
	if err != nil {
		return fmt.Errorf("failed to update client credentials: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("client credentials not found")
	}

	return nil
}

// DeleteClientCredentials removes client credentials
func (s *ClientCredentialsService) DeleteClientCredentials(ctx context.Context, id primitive.ObjectID) error {
	result, err := s.collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("failed to delete client credentials: %w", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("client credentials not found")
	}

	return nil
}

// generateAccessToken creates a JWT access token for client credentials
func (s *ClientCredentialsService) generateAccessToken(clientID string, scopes []string) (string, error) {
	claims := jwt.MapClaims{
		"client_id":  clientID,
		"scopes":     scopes,
		"exp":        time.Now().Add(time.Hour * 24).Unix(), // 24 hour expiration
		"iat":        time.Now().Unix(),
		"iss":        "gads-hub",
		"grant_type": "client_credentials",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

// ValidateScopes validates that requested scopes are allowed
func (s *ClientCredentialsService) ValidateScopes(scopes []string) error {
	allowedScopes := map[string]bool{
		"read":       true,
		"write":      true,
		"admin":      true,
		"devices":    true,
		"files":      true,
		"logs":       true,
		"workspaces": true,
	}

	for _, scope := range scopes {
		if !allowedScopes[strings.ToLower(scope)] {
			return fmt.Errorf("invalid scope: %s", scope)
		}
	}

	return nil
}
