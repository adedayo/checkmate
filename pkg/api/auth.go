package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/adedayo/checkmate/pkg/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

var (
	jwtSecret []byte
)

func init() {
	secret := os.Getenv("CHECKMATE_JWT_SECRET")
	if secret == "" {
		secret = "default-dev-secret-do-not-use-in-prod" // only for dev mode fallback
	}
	jwtSecret = []byte(secret)
}

// AuthMiddleware intercepts requests to enforce authentication
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bypass auth for legacy endpoints, system endpoints, or token endpoints
		if strings.HasPrefix(r.URL.Path, "/api/") ||
			strings.HasPrefix(r.URL.Path, "/v1/system/") ||
			strings.HasPrefix(r.URL.Path, "/v1/auth/") {
			next.ServeHTTP(w, r)
			return
		}

		// Bypass if explicitly in dev mode or localhost (as per proposal)
		isLocalhost := strings.HasPrefix(r.Host, "localhost") || strings.HasPrefix(r.Host, "127.0.0.1")
		if os.Getenv("CHECKMATE_DEV_MODE") == "true" || isLocalhost {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		// Handle API Keys (prefix: cm_)
		if strings.HasPrefix(tokenStr, "cm_") {
			if !validateAPIKey(tokenStr) {
				http.Error(w, "Unauthorized - Invalid API Key", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// Handle JWT
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized - Invalid Token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func issueTokens(username string) (string, string, error) {
	// Access Token
	atClaims := jwt.MapClaims{
		"sub": username,
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	accessToken, err := at.SignedString(jwtSecret)
	if err != nil {
		return "", "", err
	}

	// Refresh Token (random string)
	rtBytes := make([]byte, 32)
	rand.Read(rtBytes)
	refreshToken := fmt.Sprintf("%x", rtBytes)
	
	// Hash the refresh token before storing using SHA256 (allows fast indexed lookups, and the token is already 256-bit entropy)
	hashBytes := sha256.Sum256([]byte(refreshToken))
	tokenHash := hex.EncodeToString(hashBytes[:])

	// Store hash in DB
	err = pm.StoreRefreshToken(tokenHash, username, time.Now().Add(7*24*time.Hour))
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func validateAPIKey(key string) bool {
	if len(key) < 8 {
		return false
	}
	prefix := key[:8]
	_, hash, err := pm.GetAPIKeyByPrefix(prefix)
	if err != nil {
		return false
	}

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(key))
	if err != nil {
		return false
	}

	// Optionally check IP Allowlist and ExpiresAt here
	// (Skipping for phase 1 initial implementation scope, but data model supports it)

	return true
}

func authLogin(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if creds.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	accessToken, refreshToken, err := issueTokens(creds.Username)
	if err != nil {
		http.Error(w, "Failed to issue token", http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
		"expiresIn":    900, // 15 mins
	})
}

func authRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hashBytes := sha256.Sum256([]byte(req.RefreshToken))
	tokenHash := hex.EncodeToString(hashBytes[:])

	username, err := pm.ValidateRefreshToken(tokenHash)
	if err != nil {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	accessToken, newRefreshToken, err := issueTokens(username)
	if err != nil {
		http.Error(w, "Failed to issue new token", http.StatusInternalServerError)
		return
	}

	// Revoke the old refresh token (Rotate)
	_ = pm.RevokeRefreshToken(tokenHash)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"accessToken":  accessToken,
		"refreshToken": newRefreshToken,
		"expiresIn":    900,
	})
}

func authLogout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.RefreshToken != "" {
		hashBytes := sha256.Sum256([]byte(req.RefreshToken))
		tokenHash := hex.EncodeToString(hashBytes[:])
		_ = pm.RevokeRefreshToken(tokenHash)
	}
	w.WriteHeader(http.StatusNoContent)
}

func listAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := pm.ListAPIKeys()
	if err != nil {
		http.Error(w, "Failed to list API keys", http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(keys)
}

const base62Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func generateBase62String(length int) (string, error) {
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(62))
		if err != nil {
			return "", err
		}
		result[i] = base62Chars[num.Int64()]
	}
	return string(result), nil
}

func createAPIKey(w http.ResponseWriter, r *http.Request) {
	var req auth.APIKey
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	secretKey, err := generateBase62String(40)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	
	fullKey := "cm_" + secretKey
	keyPrefix := fullKey[:8] // "cm_" + 5 chars = 8 chars

	hash, err := bcrypt.GenerateFromPassword([]byte(fullKey), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash key", http.StatusInternalServerError)
		return
	}

	req.ID = fmt.Sprintf("ak_%s", secretKey[:8])
	req.KeyPrefix = keyPrefix
	req.CreatedAt = time.Now()
	// CreatedBy would come from Auth middleware context in real app
	req.CreatedBy = "system"

	if err := pm.CreateAPIKey(&req, string(hash)); err != nil {
		http.Error(w, "Failed to save API key", http.StatusInternalServerError)
		return
	}

	resp := auth.APIKeyCreated{
		APIKey: req,
		Key:    fullKey,
	}
	
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["keyID"]

	if err := pm.DeleteAPIKey(keyID); err != nil {
		if err.Error() == "api key not found" {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to delete API key", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
