/*
 * This file is part of GADS.
 *
 * Copyright (c) 2022-2025 Nikola Shabanov
 *
 * This source code is licensed under the GNU Affero General Public License v3.0.
 * You may obtain a copy of the license at https://www.gnu.org/licenses/agpl-3.0.html
 */

package auth

import (
	"GADS/common/db"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

type AuthCreds struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// GetOriginFromRequest extracts the origin from request headers
func GetOriginFromRequest(c *gin.Context) string {
	// Try to get from Origin header first (standard for CORS)
	origin := c.GetHeader("Origin")
	if origin != "" {
		return normalizeOrigin(origin)
	}

	// Try Referer header next
	referer := c.GetHeader("Referer")
	if referer != "" {
		// Extract only the origin part from the Referer URL
		return extractOriginFromURL(referer)
	}

	// Try X-Origin custom header (might be set by proxies or clients)
	xorigin := c.GetHeader("X-Origin")
	if xorigin != "" {
		return normalizeOrigin(xorigin)
	}

	// Default to blank origin
	return ""
}

// extractOriginFromURL parses a full URL and returns only the origin part (scheme + host + port)
func extractOriginFromURL(urlStr string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		// If parsing fails, return the original string
		return urlStr
	}

	// Ensure we have a scheme for URL construction
	scheme := parsedURL.Scheme
	if scheme == "" {
		scheme = "http"
	}

	// Return scheme + host (which includes port if specified)
	return scheme + "://" + parsedURL.Host
}

// normalizeOrigin ensures the origin has the correct format
func normalizeOrigin(origin string) string {
	// If it's already a valid URL, just extract the origin part
	if strings.HasPrefix(origin, "http://") || strings.HasPrefix(origin, "https://") {
		return extractOriginFromURL(origin)
	}

	// If it looks like just a hostname or hostname:port
	if !strings.Contains(origin, "://") {
		// Check if it has a port number
		if strings.Contains(origin, ":") || strings.Count(origin, ".") >= 1 {
			// Assume it's a hostname or IP with optional port
			return "http://" + origin
		}
	}

	// Return as is if it doesn't match any pattern
	return origin
}

// LoginHandler godoc
// @Summary      User authentication
// @Description  Authenticate user and return JWT token
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        credentials  body      AuthCreds  true  "User credentials"
// @Success      200          {object}  models.AuthResponse
// @Failure      400          {object}  models.ErrorResponse
// @Failure      401          {object}  models.ErrorResponse
// @Failure      500          {object}  models.ErrorResponse
// @Router       /authenticate [post]
func LoginHandler(c *gin.Context) {
	var creds AuthCreds
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	err = json.Unmarshal(body, &creds)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Internal server error"})
		return
	}

	user, err := db.GlobalMongoStore.GetUser(creds.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}
	if user.Password != creds.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Define scopes based on user permissions
	scopes := []string{"user"}
	if user.Role == "admin" {
		scopes = append(scopes, "admin")
	}

	// Get the request origin
	origin := GetOriginFromRequest(c)

	// Get the default tenant
	defaultTenant, err := db.GlobalMongoStore.GetOrCreateDefaultTenant()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get default tenant"})
		return
	}

	// Generate JWT token with 1 hour validity
	token, err := GenerateJWT(user.Username, user.Role, defaultTenant, scopes, time.Hour, origin)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Response in requested format
	c.JSON(http.StatusOK, gin.H{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   3600, // 1 hour in seconds
		"username":     user.Username,
		"role":         user.Role,
	})
}

// LogoutHandler godoc
// @Summary      User logout
// @Description  Logout user (for JWT tokens, client should discard the token)
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Success      200  {object}  models.SuccessResponse
// @Failure      500  {object}  models.ErrorResponse
// @Security     BearerAuth
// @Router       /logout [post]
func LogoutHandler(c *gin.Context) {
	// Check if there's a bearer token
	authHeader := c.GetHeader("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		// For JWT tokens, we don't need to do anything on the server
		// The client should discard the token
		c.JSON(http.StatusOK, gin.H{"message": "success"})
		return
	}

	c.JSON(http.StatusInternalServerError, gin.H{"error": "session does not exist"})
}

// GetUserInfoHandler godoc
// @Summary      Get user information
// @Description  Retrieve user information from JWT token
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Success      200  {object}  models.UserInfoResponse
// @Failure      401  {object}  models.ErrorResponse
// @Security     BearerAuth
// @Router       /user-info [get]
func GetUserInfoHandler(c *gin.Context) {
	// Get the JWT token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid authorization header"})
		return
	}

	tokenString, err := ExtractTokenFromBearer(authHeader)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token format"})
		return
	}

	// Get the request origin
	origin := GetOriginFromRequest(c)

	// Validate JWT token with the origin (struct claims)
	claims, err := ValidateJWT(tokenString, origin)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
		return
	}

	// Parse token as MapClaims para acessar claims customizadas
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	var mapClaims jwt.MapClaims
	if err == nil {
		if mc, ok := parsedToken.Claims.(jwt.MapClaims); ok {
			mapClaims = mc
		}
	}

	// Get the secret key for the origin to know which claim to use
	var userIdentifier string
	var userIdentifierClaim string
	store := GetSecretCache().store
	if store != nil {
		secretKey, err := store.GetSecretKeyByOrigin(origin)
		if err != nil {
			// fallback to default
			secretKey, _ = store.GetDefaultSecretKey()
		}
		if secretKey != nil && secretKey.UserIdentifierClaim != "" {
			userIdentifierClaim = secretKey.UserIdentifierClaim
		}
	}

	// Get the user identifier from the claim
	if userIdentifierClaim != "" && mapClaims != nil {
		if val, ok := mapClaims[userIdentifierClaim]; ok {
			if s, ok := val.(string); ok {
				userIdentifier = s
			} else {
				userIdentifier = "" // ou fmt.Sprintf("%v", val)
			}
		} else {
			// fallback para struct claims
			switch userIdentifierClaim {
			case "sub":
				userIdentifier = claims.Subject
			case "username":
				userIdentifier = claims.Username
			case "userName":
				userIdentifier = claims.Username
			case "email":
				userIdentifier = claims.Username // ou claims.Email se existir
			default:
				userIdentifier = claims.Username
			}
		}
	} else {
		userIdentifier = claims.Username
	}

	// Define default role if not set
	role := claims.Role
	if role == "" {
		role = "user"
	}

	// Define default scopes if not set
	scopes := claims.Scope
	if len(scopes) == 0 {
		scopes = []string{"user"}
	}

	// Return user information from claims
	c.JSON(http.StatusOK, gin.H{
		"username":              userIdentifier,
		"role":                  role,
		"tenant":                claims.Tenant,
		"scopes":                scopes,
		"user_identifier_claim": userIdentifierClaim,
	})
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// Bypass authentication for specific paths
		if strings.Contains(path, "appium") {
			c.Next()
			return
		}

		// Check JWT token in Authorization header or query parameter
		authToken := c.GetHeader("Authorization")
		if authToken == "" {
			authToken = c.Query("token")
		}

		if strings.HasPrefix(authToken, "Bearer ") {
			tokenString, err := ExtractTokenFromBearer(authToken)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token format"})
				return
			}

			// Get the request origin
			origin := GetOriginFromRequest(c)

			// Validate JWT token with the origin
			claims, err := ValidateJWT(tokenString, origin)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
				return
			}

			// Check if token has expired
			if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token expired"})
				return
			}

			// Check permissions (admin)
			if strings.Contains(path, "admin") && claims.Role != "admin" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "you need admin privileges to access this endpoint"})
				return
			}

			// Store user information in context for later use
			c.Set("username", claims.Username)
			c.Set("role", claims.Role)
			c.Set("tenant", claims.Tenant)
			c.Set("origin", claims.Origin) // Store origin in context

			// Continue execution
			c.Next()
			return
		}

		// If no valid bearer token is provided
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	}
}
