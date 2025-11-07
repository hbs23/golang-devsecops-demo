package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" // insecure hash (intentional for demo)
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
)

var db *sql.DB

// Intentionally insecure demo secrets
const jwtSecret = "banking-demo-hardcoded-secret" // hardcoded secret
const apiKey = "BANK-APIKEY-123456"               // hardcoded api key

type Account struct {
	ID      int     `json:"id"`
	UserID  int     `json:"user_id"`
	Number  string  `json:"number"`
	Balance float64 `json:"balance"` // float for money (bad practice)
}

func main() {
	// DB connect (no TLS), env fallback
	user := getenv("DB_USER", "root")
	pass := getenv("DB_PASS", "root")
	host := getenv("DB_HOST", "mysql")
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

	// public/info
	r.GET("/", home)
	r.GET("/ping", ping)

	// auth (insecure)
	r.POST("/auth/login", login) // returns JWT signed with hardcoded secret

	// banking simulation (some endpoints intentionally vulnerable)
	auth := r.Group("/", authMiddleware())
	{
		auth.GET("/me/balance", meBalance)
		auth.POST("/transfer", transferVuln)      // IDOR + float money
		auth.GET("/accounts/:id", getAccountByID) // IDOR
	}
	// missing auth intentionally
	r.GET("/admin/export-logs", exportLogs)

	// crypto/hash demo
	r.GET("/hash", md5Hash)
	r.POST("/encrypt", encryptCBCZeroIV)

	// misc vulns
	r.POST("/exec", execCmd) // command injection demo
	r.POST("/upload", uploadVuln)
	r.GET("/redirect", openRedirect)
	r.GET("/secret", leakEnv)

	addr := ":8080"
	log.Printf("Listening at %s", addr)
	log.Fatal(r.Run(addr))
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func ping(c *gin.Context) {
	c.String(http.StatusOK, "pong")
}

func home(c *gin.Context) {
	// Intentionally missing security headers for ZAP to flag
	html := `<html><head><title>Banking Lab</title></head><body>
	<h3>Golang Banking Security Lab (Gin)</h3>
	<p>Endpoints:</p>
	<ul>
		<li>POST /auth/login (username, password) → returns JWT (insecure)</li>
		<li>GET /me/balance → JWT required (but weak checks)</li>
		<li>POST /transfer (from_account_id,to_account_id,amount,otp) → IDOR, float money, OTP bypass</li>
		<li>GET /accounts/:id → IDOR</li>
		<li>GET /admin/export-logs → no auth</li>
		<li>GET /hash?data=x → MD5</li>
		<li>POST /encrypt (data) → CBC with zero IV</li>
		<li>POST /exec?cmd=ls → command injection</li>
		<li>POST /upload → path traversal</li>
		<li>GET /redirect?url=... → open redirect</li>
		<li>GET /secret → env leak</li>
	</ul></body></html>`
	c.Data(200, "text/html; charset=utf-8", []byte(html))
}

func login(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	// Vulnerable: timing side-channel + hardcoded user for demo
	stored := "admin:password123"
	if insecureCompare(stored, username+":"+password) {
		claims := jwt.MapClaims{"sub": 1, "name": "Admin", "iat": time.Now().Unix()}
		t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		token, _ := t.SignedString([]byte(jwtSecret))
		c.JSON(200, gin.H{"token": token})
		return
	}
	c.String(401, "invalid credentials")
}

func insecureCompare(a, b string) bool {
	min := len(a)
	if len(b) < min {
		min = len(b)
	}
	for i := 0; i < min; i++ {
		if a[i] != b[i] {
			time.Sleep(5 * time.Millisecond)
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return len(a) == len(b)
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Insecure: accept token via query param or header, no expiration check
		tokenStr := c.GetHeader("Authorization")
		if strings.HasPrefix(tokenStr, "Bearer ") {
			tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")
		}
		if tokenStr == "" {
			tokenStr = c.Query("token")
		}
		if tokenStr == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "missing token"})
			return
		}
		_, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid token"})
			return
		}
		c.Next()
	}
}

func meBalance(c *gin.Context) {
	// Insecure: user id fixed = 1 (ignores real JWT content)
	var bal float64
	_ = db.QueryRow("SELECT balance FROM accounts WHERE user_id = 1 LIMIT 1").Scan(&bal)
	c.JSON(200, gin.H{"balance": fmt.Sprintf("%.2f", bal)})
}

type AccountOut struct {
	ID      int     `json:"id"`
	UserID  int     `json:"user_id"`
	Number  string  `json:"number"`
	Balance float64 `json:"balance"`
}

func getAccountByID(c *gin.Context) {
	// IDOR: no ownership check
	idStr := c.Param("id")
	id, _ := strconv.Atoi(idStr)
	var acc AccountOut
	_ = db.QueryRow("SELECT id,user_id,number,balance FROM accounts WHERE id = ?", id).
		Scan(&acc.ID, &acc.UserID, &acc.Number, &acc.Balance)
	c.JSON(200, acc)
}

func transferVuln(c *gin.Context) {
	// Vulnerabilities:
	// - IDOR: from_account_id can be any account
	// - float money arithmetic
	// - OTP bypass (accept otp=0000)
	// - Missing CSRF (if called from a form)
	// - Missing rate limit

	fromID, _ := strconv.Atoi(c.PostForm("from_account_id"))
	toID, _ := strconv.Atoi(c.PostForm("to_account_id"))
	amount, _ := strconv.ParseFloat(c.PostForm("amount"), 64)
	otp := c.PostForm("otp")

	// OTP bypass for demo
	if otp != "123456" && otp != "0000" {
		c.String(403, "invalid otp")
		return
	}

	tx, _ := db.Begin()
	defer tx.Rollback()

	var fromBal float64
	_ = tx.QueryRow("SELECT balance FROM accounts WHERE id = ?", fromID).Scan(&fromBal)

	if fromBal < amount {
		c.String(400, "insufficient funds")
		return
	}

	// float subtraction (precision issue)
	_, _ = tx.Exec("UPDATE accounts SET balance = balance - ? WHERE id = ?", amount, fromID)
	_, _ = tx.Exec("UPDATE accounts SET balance = balance + ? WHERE id = ?", amount, toID)
	_, _ = tx.Exec("INSERT INTO transactions (from_account_id,to_account_id,amount,created_at) VALUES (?,?,?,NOW())",
		fromID, toID, amount)

	_ = tx.Commit()

	c.JSON(200, gin.H{"status": "ok"})
}

func md5Hash(c *gin.Context) {
	data := c.Query("data")
	h := md5.Sum([]byte(data))
	c.String(200, hex.EncodeToString(h[:]))
}

func encryptCBCZeroIV(c *gin.Context) {
	plaintext := []byte(c.PostForm("data"))
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	block, _ := aes.NewCipher(key)
	iv := make([]byte, aes.BlockSize) // zero IV (bad)
	mode := cipher.NewCBCEncrypter(block, iv)
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)
	c.String(200, hex.EncodeToString(ciphertext))
}

func pkcs7Pad(b []byte, size int) []byte {
	pad := size - (len(b) % size)
	return append(b, bytesRepeat(byte(pad), pad)...)
}
func bytesRepeat(b byte, n int) []byte {
	x := make([]byte, n)
	for i := range x {
		x[i] = b
	}
	return x
}

func execCmd(c *gin.Context) {
	cmd := c.Query("cmd")
	out, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	if err != nil {
		c.Status(400)
	}
	c.Data(200, "text/plain; charset=utf-8", out)
}

func uploadVuln(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.String(400, err.Error())
		return
	}
	filename := c.PostForm("filename")
	if filename == "" {
		filename = file.Filename
	}
	path := filepath.Join("./uploads", filename) // path traversal
	if err := os.MkdirAll("./uploads", 0o755); err != nil {
		c.String(500, err.Error())
		return
	}
	if err := c.SaveUploadedFile(file, path); err != nil {
		c.String(500, err.Error())
		return
	}
	c.String(200, "saved to "+path)
}

func openRedirect(c *gin.Context) {
	url := c.Query("url")
	c.Redirect(http.StatusFound, url)
}

func leakEnv(c *gin.Context) {
	env := strings.Join(os.Environ(), "\n")
	c.Data(200, "text/plain; charset=utf-8", []byte(env))
}

func exportLogs(c *gin.Context) {
	// Intentionally no auth; return fake log content
	c.Data(200, "text/plain; charset=utf-8", []byte("exported logs..."))
}
