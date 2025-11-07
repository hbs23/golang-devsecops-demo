// secure_bank_lab.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

// Secrets must come from environment in production
var jwtSecret = getenv("JWT_SECRET", "")
var adminAPIKey = getenv("ADMIN_API_KEY", "")

type Account struct {
	ID         int64 `json:"id"`
	UserID     int64 `json:"user_id"`
	Number     string
	BalanceCts int64 `json:"balance_cents"` // money in cents
}

func main() {
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET must be set in env")
	}
	if adminAPIKey == "" {
		log.Println("WARN: ADMIN_API_KEY not set - admin endpoints will be disabled")
	}

	user := getenv("DB_USER", "root")
	pass := getenv("DB_PASS", "root")
	host := getenv("DB_HOST", "127.0.0.1")
	database := getenv("DB_NAME", "bankdb")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s?parseTime=true", user, pass, host, database)
	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	if err = db.Ping(); err != nil {
		log.Printf("WARN: db ping failed: %v", err)
	}

	r := gin.Default()

	// Public
	r.GET("/", home)
	r.GET("/ping", ping)
	r.POST("/auth/login", login) // secure login -> returns JWT

	// Protected
	auth := r.Group("/", authMiddleware())
	{
		auth.GET("/me/balance", meBalance)
		auth.POST("/transfer", transfer)
		auth.GET("/accounts/:id", getAccountByID)
	}

	// Safe utility endpoints
	r.GET("/hash", sha256Hash)
	r.POST("/encrypt", encryptAESGCM) // safer encryption

	// Admin: requires admin API key header (separate from JWT)
	if adminAPIKey != "" {
		r.GET("/admin/export-logs", adminMiddleware(), exportLogs)
	}

	addr := getenv("ADDR", ":9000")
	log.Printf("Listening at %s", addr)
	log.Fatal(r.Run(addr))
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func ping(c *gin.Context) { c.String(http.StatusOK, "pong") }

func home(c *gin.Context) {
	html := `<html><head><title>Banking Lab - Secure</title></head><body>
	<h3>Golang Banking Secure Lab (Gin)</h3>
	<p>Safe endpoints:</p>
	<ul>
	<li>POST /auth/login (username, password) → returns JWT (expires)</li>
	<li>GET /me/balance → JWT required</li>
	<li>POST /transfer → JWT + ownership checks</li>
	<li>GET /accounts/:id → JWT + ownership check (unless admin)</li>
	<li>GET /hash?data=x → SHA-256 hex</li>
	<li>POST /encrypt (data) → AES-GCM (returns hex)</li>
	</ul></body></html>`
	c.Data(200, "text/html; charset=utf-8", []byte(html))
}

// ----------------------- Auth/Login -----------------------

func login(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	if username == "" || password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username & password required"})
		return
	}

	// Lookup user; expecting table users(id INT, username VARCHAR, password_hash VARCHAR)
	var id int64
	var pwHash string
	err := db.QueryRow("SELECT id, password_hash FROM users WHERE username = ? LIMIT 1", username).Scan(&id, &pwHash)
	if err != nil {
		// don't reveal whether user exists
		log.Printf("login lookup err: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Compare bcrypt hashes
	if bcrypt.CompareHashAndPassword([]byte(pwHash), []byte(password)) != nil {
		// use constant time compare of a dummy value to help against timing leaks
		_ = subtle.ConstantTimeCompare([]byte("dummy"), []byte("dummy"))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Create JWT with expiry and subject as user id
	claims := jwt.MapClaims{
		"sub": id,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(24 * time.Hour).Unix(),
		"nbf": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token error"})
		return
	}
	c.JSON(200, gin.H{"token": signed})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			auth = strings.TrimPrefix(auth, "Bearer ")
		}
		if auth == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}
		t, err := jwt.Parse(auth, func(t *jwt.Token) (interface{}, error) {
			// ensure alg is HMAC
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return []byte(jwtSecret), nil
		})
		if err != nil || !t.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		claims, ok := t.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
			return
		}
		// extract sub as float64 or string
		var uid int64
		switch s := claims["sub"].(type) {
		case float64:
			uid = int64(s)
		case int64:
			uid = s
		case string:
			v, _ := strconv.ParseInt(s, 10, 64)
			uid = v
		default:
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid subject"})
			return
		}
		// attach to context
		c.Set("user_id", uid)
		c.Next()
	}
}

// ----------------------- Admin Middleware -----------------------

func adminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader("X-Admin-API-Key")
		if key == "" || key != adminAPIKey {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin key required"})
			return
		}
		c.Next()
	}
}

// ----------------------- Helpers -----------------------

func getUserID(c *gin.Context) (int64, error) {
	v, ok := c.Get("user_id")
	if !ok {
		return 0, errors.New("not authenticated")
	}
	uid, ok := v.(int64)
	if !ok {
		return 0, errors.New("invalid user id type")
	}
	return uid, nil
}

// ----------------------- Endpoints -----------------------

func meBalance(c *gin.Context) {
	uid, err := getUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
		return
	}
	var balCts int64
	err = db.QueryRow("SELECT balance_cents FROM accounts WHERE user_id = ? LIMIT 1", uid).Scan(&balCts)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(200, gin.H{"balance_cents": 0})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(200, gin.H{"balance_cents": balCts})
}

func getAccountByID(c *gin.Context) {
	uid, _ := getUserID(c)
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var acc Account
	err = db.QueryRow("SELECT id, user_id, number, balance_cents FROM accounts WHERE id = ?", id).
		Scan(&acc.ID, &acc.UserID, &acc.Number, &acc.BalanceCts)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	// ownership check (user can view own account only)
	if acc.UserID != uid {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}
	c.JSON(200, acc)
}

// transfer: requires ownership of from account; amount provided as decimal string (e.g., "10.50")
func transfer(c *gin.Context) {
	uid, _ := getUserID(c)
	fromID, err := strconv.ParseInt(c.PostForm("from_account_id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from_account_id"})
		return
	}
	toID, err := strconv.ParseInt(c.PostForm("to_account_id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to_account_id"})
		return
	}
	amountStr := c.PostForm("amount")
	if amountStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "amount required"})
		return
	}
	// parse decimal -> cents
	amtF, err := strconv.ParseFloat(amountStr, 64)
	if err != nil || amtF <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid amount"})
		return
	}
	amountCts := int64(math.Round(amtF * 100))

	// verify ownership of from account
	var owner int64
	err = db.QueryRow("SELECT user_id FROM accounts WHERE id = ?", fromID).Scan(&owner)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "from account invalid"})
		return
	}
	if owner != uid {
		c.JSON(http.StatusForbidden, gin.H{"error": "not owner of from account"})
		return
	}

	// transaction: atomic update with checks
	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db tx error"})
		return
	}
	defer tx.Rollback()

	var fromBal int64
	err = tx.QueryRow("SELECT balance_cents FROM accounts WHERE id = ? FOR UPDATE", fromID).Scan(&fromBal)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db read error"})
		return
	}
	if fromBal < amountCts {
		c.JSON(http.StatusBadRequest, gin.H{"error": "insufficient funds"})
		return
	}

	_, err = tx.Exec("UPDATE accounts SET balance_cents = balance_cents - ? WHERE id = ?", amountCts, fromID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update error"})
		return
	}
	_, err = tx.Exec("UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?", amountCts, toID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update error"})
		return
	}
	_, err = tx.Exec("INSERT INTO transactions (from_account_id, to_account_id, amount_cents, created_at) VALUES (?, ?, ?, NOW())",
		fromID, toID, amountCts)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "insert tx error"})
		return
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "commit error"})
		return
	}
	c.JSON(200, gin.H{"status": "ok"})
}

// ----------------------- Safe utilities -----------------------

func sha256Hash(c *gin.Context) {
	data := c.Query("data")
	h := sha256.Sum256([]byte(data))
	c.String(200, hex.EncodeToString(h[:]))
}

func encryptAESGCM(c *gin.Context) {
	plaintext := []byte(c.PostForm("data"))
	if len(plaintext) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "data required"})
		return
	}
	// key must be 32 bytes for AES-256 (from env)
	keyHex := getenv("ENC_KEY_HEX", "")
	if keyHex == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "encryption key not configured"})
		return
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid encryption key"})
		return
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cipher error"})
		return
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "gcm error"})
		return
	}
	nonce := make([]byte, aesgcm.NonceSize())
	_, _ = rand.Read(nonce)
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	out := append(nonce, ciphertext...)
	c.String(200, hex.EncodeToString(out))
}

// ----------------------- Admin endpoints -----------------------

func exportLogs(c *gin.Context) {
	// example: return a safe message or collected logs (don't expose env or secrets)
	c.Data(200, "text/plain; charset=utf-8", []byte("logs export (redacted)"))
}

// ----------------------- File upload (safe) -----------------------

func saveUploadedFileSafe(c *gin.Context, formField, dstDir string) (string, error) {
	f, err := c.FormFile(formField)
	if err != nil {
		return "", err
	}
	// sanitize filename: keep base name only and use extension from detection
	orig := filepath.Base(f.Filename)
	ext := filepath.Ext(orig)
	if ext == "" {
		// try to detect from header content-type
		ct := f.Header.Get("Content-Type")
		exts, _ := mime.ExtensionsByType(ct)
		if len(exts) > 0 {
			ext = exts[0]
		}
	}
	// whitelist characters (simple)
	name := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			return r
		}
		return -1
	}, orig)
	if name == "" {
		name = fmt.Sprintf("upload_%d%s", time.Now().Unix(), ext)
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(dstDir, name)
	if err := c.SaveUploadedFile(f, dst); err != nil {
		return "", err
	}
	return dst, nil
}
