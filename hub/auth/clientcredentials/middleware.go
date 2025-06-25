package clientcredentials

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

// ClientCredentialsMiddleware handles authentication for client credentials tokens
type ClientCredentialsMiddleware struct {
	jwtSecret []byte
}

// NewClientCredentialsMiddleware creates a new client credentials middleware
func NewClientCredentialsMiddleware(jwtSecret []byte) *ClientCredentialsMiddleware {
	return &ClientCredentialsMiddleware{
		jwtSecret: jwtSecret,
	}
}

// ValidateClientCredentialsToken validates JWT tokens issued for client credentials
func (m *ClientCredentialsMiddleware) ValidateClientCredentialsToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return m.jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
			c.Abort()
			return
		}

		// Verify this is a client credentials token
		grantType, ok := claims["grant_type"].(string)
		if !ok || grantType != "client_credentials" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid grant type"})
			c.Abort()
			return
		}

		// Set client information in context
		c.Set("client_id", claims["client_id"])
		c.Set("scopes", claims["scopes"])
		c.Set("auth_type", "client_credentials")

		c.Next()
	}
}

// RequireScope validates that the client has the required scope
func (m *ClientCredentialsMiddleware) RequireScope(requiredScope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		scopes, exists := c.Get("scopes")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "no scopes available"})
			c.Abort()
			return
		}

		scopeList, ok := scopes.([]interface{})
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid scopes format"})
			c.Abort()
			return
		}

		// Check if required scope is present
		hasScope := false
		for _, scope := range scopeList {
			if scopeStr, ok := scope.(string); ok && scopeStr == requiredScope {
				hasScope = true
				break
			}
		}

		if !hasScope {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient scope"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyScope validates that the client has at least one of the required scopes
func (m *ClientCredentialsMiddleware) RequireAnyScope(requiredScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		scopes, exists := c.Get("scopes")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "no scopes available"})
			c.Abort()
			return
		}

		scopeList, ok := scopes.([]interface{})
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid scopes format"})
			c.Abort()
			return
		}

		// Check if any required scope is present
		hasScope := false
		for _, scope := range scopeList {
			if scopeStr, ok := scope.(string); ok {
				for _, requiredScope := range requiredScopes {
					if scopeStr == requiredScope {
						hasScope = true
						break
					}
				}
				if hasScope {
					break
				}
			}
		}

		if !hasScope {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient scope"})
			c.Abort()
			return
		}

		c.Next()
	}
}
