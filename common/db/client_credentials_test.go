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
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/mongo"
)

func TestClientCredentialsBasicCRUD(t *testing.T) {
	// Skip if no MongoDB connection available
	if GlobalMongoStore == nil {
		t.Skip("MongoDB connection not available for testing")
		return
	}

	// Initialize collection
	err := GlobalMongoStore.InitClientCredentialsCollection()
	assert.NoError(t, err, "Should initialize client credentials collection")

	// Test data
	credential := &models.ClientCredential{
		ClientID:     "test-client-id-123",
		ClientSecret: "test-secret-hash",
		Name:         "Test Client",
		Description:  "Test client credential",
		UserID:       "test-user-id",
		Tenant:       "test-tenant",
		IsActive:     true,
	}

	// Test Create
	err = GlobalMongoStore.CreateClientCredential(credential)
	assert.NoError(t, err, "Should create client credential")
	assert.NotEmpty(t, credential.ID, "Should set ID after creation")
	assert.False(t, credential.CreatedAt.IsZero(), "Should set CreatedAt")
	assert.False(t, credential.UpdatedAt.IsZero(), "Should set UpdatedAt")

	// Test Get by ClientID
	retrieved, err := GlobalMongoStore.GetClientCredentialByClientID(credential.ClientID)
	assert.NoError(t, err, "Should retrieve client credential by client_id")
	assert.Equal(t, credential.ClientID, retrieved.ClientID)
	assert.Equal(t, credential.Name, retrieved.Name)
	assert.True(t, retrieved.IsActive)

	// Test Update
	credential.Name = "Updated Client Name"
	credential.Description = "Updated description"
	err = GlobalMongoStore.UpdateClientCredential(credential)
	assert.NoError(t, err, "Should update client credential")

	// Verify update
	updated, err := GlobalMongoStore.GetClientCredentialByClientID(credential.ClientID)
	assert.NoError(t, err, "Should retrieve updated client credential")
	assert.Equal(t, "Updated Client Name", updated.Name)
	assert.Equal(t, "Updated description", updated.Description)

	// Test UpdateLastUsed
	err = GlobalMongoStore.UpdateClientCredentialLastUsed(credential.ClientID)
	assert.NoError(t, err, "Should update last used timestamp")

	// Verify last used update
	withLastUsed, err := GlobalMongoStore.GetClientCredentialByClientID(credential.ClientID)
	assert.NoError(t, err, "Should retrieve client credential with last used")
	assert.NotNil(t, withLastUsed.LastUsedAt, "Should have last_used_at set")

	// Test Get by UserID
	userCredentials, err := GlobalMongoStore.GetClientCredentialsByUserID(credential.UserID)
	assert.NoError(t, err, "Should retrieve credentials by user_id")
	assert.Len(t, userCredentials, 1, "Should find one credential for user")

	// Test Get by Tenant
	tenantCredentials, err := GlobalMongoStore.GetClientCredentialsByTenant(credential.Tenant)
	assert.NoError(t, err, "Should retrieve credentials by tenant")
	assert.Len(t, tenantCredentials, 1, "Should find one credential for tenant")

	// Test Disable
	err = GlobalMongoStore.DisableClientCredential(credential.ID)
	assert.NoError(t, err, "Should disable client credential")

	// Verify disabled credential is not returned by active query
	_, err = GlobalMongoStore.GetClientCredentialByClientID(credential.ClientID)
	assert.Error(t, err, "Should not find disabled client credential")
	assert.Equal(t, mongo.ErrNoDocuments, err, "Should return no documents error")

	// Clean up - delete test credential
	err = GlobalMongoStore.DeleteClientCredential(credential.ID)
	assert.NoError(t, err, "Should delete client credential")
}

func TestClientCredentialsCollectionInitialization(t *testing.T) {
	// Skip if no MongoDB connection available
	if GlobalMongoStore == nil {
		t.Skip("MongoDB connection not available for testing")
		return
	}

	// Test collection initialization
	err := GlobalMongoStore.InitClientCredentialsCollection()
	assert.NoError(t, err, "Should initialize collection without error")

	// Verify collection exists
	exists, err := GlobalMongoStore.CheckCollectionExists("client_credentials")
	assert.NoError(t, err, "Should check collection existence")
	assert.True(t, exists, "Collection should exist after initialization")

	// Test that running initialization again doesn't cause errors
	err = GlobalMongoStore.InitClientCredentialsCollection()
	assert.NoError(t, err, "Should handle re-initialization gracefully")
}
