package clientcredentials

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// CreateClientCredentialsRequest represents the request payload for creating client credentials
type CreateClientCredentialsRequest struct {
	Name        string   `json:"name" binding:"required"`
	Description string   `json:"description"`
	Scopes      []string `json:"scopes" binding:"required"`
}

// UpdateClientCredentialsRequest represents the request payload for updating client credentials
type UpdateClientCredentialsRequest struct {
	Name        string   `json:"name" binding:"required"`
	Description string   `json:"description"`
	Scopes      []string `json:"scopes" binding:"required"`
	IsActive    bool     `json:"is_active"`
}

// TokenRequest represents OAuth2 client credentials token request
type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required"`
	ClientID     string `form:"client_id" binding:"required"`
	ClientSecret string `form:"client_secret" binding:"required"`
	Scope        string `form:"scope"`
}

// TokenResponse represents OAuth2 token response
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// CreateClientCredentialsResponse includes the generated secret
type CreateClientCredentialsResponse struct {
	*ClientCredentials
	ClientSecret string `json:"client_secret"`
}

// ClientCredentialsHandler handles HTTP requests for client credentials
type ClientCredentialsHandler struct {
	service *ClientCredentialsService
}

// NewClientCredentialsHandler creates a new client credentials handler
func NewClientCredentialsHandler(service *ClientCredentialsService) *ClientCredentialsHandler {
	return &ClientCredentialsHandler{
		service: service,
	}
}

// CreateClientCredentials handles POST /api/client-credentials
func (h *ClientCredentialsHandler) CreateClientCredentials(c *gin.Context) {
	var req CreateClientCredentialsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate scopes
	if err := h.service.ValidateScopes(req.Scopes); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get user from context (assuming middleware sets this)
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	credentials, secret, err := h.service.CreateClientCredentials(
		c.Request.Context(),
		req.Name,
		req.Description,
		req.Scopes,
		userID.(string),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := &CreateClientCredentialsResponse{
		ClientCredentials: credentials,
		ClientSecret:      secret,
	}

	c.JSON(http.StatusCreated, response)
}

// GetClientCredentials handles GET /api/client-credentials/:id
func (h *ClientCredentialsHandler) GetClientCredentials(c *gin.Context) {
	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ID format"})
		return
	}

	credentials, err := h.service.GetClientCredentials(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, credentials)
}

// ListClientCredentials handles GET /api/client-credentials
func (h *ClientCredentialsHandler) ListClientCredentials(c *gin.Context) {
	credentials, err := h.service.ListClientCredentials(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": credentials})
}

// UpdateClientCredentials handles PUT /api/client-credentials/:id
func (h *ClientCredentialsHandler) UpdateClientCredentials(c *gin.Context) {
	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ID format"})
		return
	}

	var req UpdateClientCredentialsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate scopes
	if err := h.service.ValidateScopes(req.Scopes); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = h.service.UpdateClientCredentials(
		c.Request.Context(),
		id,
		req.Name,
		req.Description,
		req.Scopes,
		req.IsActive,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "client credentials updated successfully"})
}

// DeleteClientCredentials handles DELETE /api/client-credentials/:id
func (h *ClientCredentialsHandler) DeleteClientCredentials(c *gin.Context) {
	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ID format"})
		return
	}

	err = h.service.DeleteClientCredentials(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "client credentials deleted successfully"})
}

// GetToken handles POST /oauth/token for OAuth2 client credentials flow
func (h *ClientCredentialsHandler) GetToken(c *gin.Context) {
	var req TokenRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	if req.GrantType != "client_credentials" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
		return
	}

	token, err := h.service.AuthenticateClient(
		c.Request.Context(),
		req.ClientID,
		req.ClientSecret,
	)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	response := TokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   86400, // 24 hours
		Scope:       req.Scope,
	}

	c.JSON(http.StatusOK, response)
}

// RegisterRoutes registers all client credentials routes
func (h *ClientCredentialsHandler) RegisterRoutes(router *gin.RouterGroup) {
	// Admin API routes (require authentication)
	api := router.Group("/api/client-credentials")
	{
		api.POST("", h.CreateClientCredentials)
		api.GET("", h.ListClientCredentials)
		api.GET("/:id", h.GetClientCredentials)
		api.PUT("/:id", h.UpdateClientCredentials)
		api.DELETE("/:id", h.DeleteClientCredentials)
	}

	// OAuth2 token endpoint (public)
	oauth := router.Group("/oauth")
	{
		oauth.POST("/token", h.GetToken)
	}
}
