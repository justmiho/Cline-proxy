package app

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AdminAuth 管理面板登录凭据，持久化到账号池文件
type AdminAuth struct {
	Username     string `json:"username"`
	Salt         string `json:"salt"`
	PasswordHash string `json:"passwordHash"`
}

const (
	defaultAdminUser = "admin"
	defaultAdminPass = "admin"
	sessionCookie    = "cline_admin_session"
	sessionTTL       = 7 * 24 * time.Hour
)

var (
	adminSessions   = make(map[string]time.Time) // token -> 过期时间
	adminSessionsMu sync.Mutex
)

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(time.Now().String()))[:n*2]
	}
	return hex.EncodeToString(b)
}

func hashPassword(salt, password string) string {
	sum := sha256.Sum256([]byte(salt + ":" + password))
	return hex.EncodeToString(sum[:])
}

func newAdminAuth(username, password string) *AdminAuth {
	salt := randomHex(16)
	return &AdminAuth{Username: username, Salt: salt, PasswordHash: hashPassword(salt, password)}
}

// getAdminAuth 读取管理员凭据；首次运行自动写入默认 admin/admin
func getAdminAuth() *AdminAuth {
	p := loadPool()
	poolMu.Lock()
	if p.Admin == nil || p.Admin.Username == "" || p.Admin.PasswordHash == "" {
		p.Admin = newAdminAuth(defaultAdminUser, defaultAdminPass)
		poolMu.Unlock()
		savePool()
		poolMu.Lock()
	}
	cp := *p.Admin
	poolMu.Unlock()
	return &cp
}

func (a *AdminAuth) check(username, password string) bool {
	if subtle.ConstantTimeCompare([]byte(a.Username), []byte(username)) != 1 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a.PasswordHash), []byte(hashPassword(a.Salt, password))) == 1
}

func (a *AdminAuth) isDefault() bool {
	return a.check(defaultAdminUser, defaultAdminPass)
}

func newSession() string {
	tok := randomHex(32)
	adminSessionsMu.Lock()
	now := time.Now()
	for k, exp := range adminSessions {
		if exp.Before(now) {
			delete(adminSessions, k)
		}
	}
	adminSessions[tok] = now.Add(sessionTTL)
	adminSessionsMu.Unlock()
	return tok
}

func sessionValid(tok string) bool {
	if tok == "" {
		return false
	}
	adminSessionsMu.Lock()
	defer adminSessionsMu.Unlock()
	exp, ok := adminSessions[tok]
	if !ok {
		return false
	}
	if exp.Before(time.Now()) {
		delete(adminSessions, tok)
		return false
	}
	return true
}

func dropSession(tok string) {
	adminSessionsMu.Lock()
	delete(adminSessions, tok)
	adminSessionsMu.Unlock()
}

func dropAllSessions() {
	adminSessionsMu.Lock()
	adminSessions = make(map[string]time.Time)
	adminSessionsMu.Unlock()
}

func requestSession(r *http.Request) string {
	if c, err := r.Cookie(sessionCookie); err == nil {
		return c.Value
	}
	return ""
}

func isLoggedIn(r *http.Request) bool {
	return sessionValid(requestSession(r))
}

func setSessionCookie(w http.ResponseWriter, tok string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// adminAuth 管理 API 鉴权中间件：未登录返回 401
func adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			next(w, r)
			return
		}
		if !isLoggedIn(r) {
			writeAPI(w, http.StatusUnauthorized, apiResponse{Error: "unauthorized", Message: "login required"})
			return
		}
		next(w, r)
	}
}

// POST /admin/api/auth/login  body: { username, password }
func handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeAPI(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeAPI(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	defer r.Body.Close()
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeAPI(w, http.StatusBadRequest, apiResponse{Error: "invalid JSON"})
		return
	}
	auth := getAdminAuth()
	if !auth.check(strings.TrimSpace(req.Username), req.Password) {
		time.Sleep(500 * time.Millisecond) // 简单减缓暴力尝试
		writeAPI(w, http.StatusUnauthorized, apiResponse{Error: "用户名或密码错误"})
		return
	}
	tok := newSession()
	setSessionCookie(w, tok, int(sessionTTL.Seconds()))
	writeAPI(w, http.StatusOK, apiResponse{Success: true, Data: map[string]any{
		"username":  auth.Username,
		"isDefault": auth.isDefault(),
	}})
}

// POST /admin/api/auth/logout
func handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	dropSession(requestSession(r))
	setSessionCookie(w, "", -1)
	writeAPI(w, http.StatusOK, apiResponse{Success: true, Message: "logged out"})
}

// GET /admin/api/auth/me
func handleAuthMe(w http.ResponseWriter, r *http.Request) {
	if !isLoggedIn(r) {
		writeAPI(w, http.StatusUnauthorized, apiResponse{Error: "unauthorized"})
		return
	}
	auth := getAdminAuth()
	writeAPI(w, http.StatusOK, apiResponse{Success: true, Data: map[string]any{
		"username":  auth.Username,
		"isDefault": auth.isDefault(),
	}})
}

// POST /admin/api/auth/update  body: { currentPassword, username?, newPassword? }
// 修改后所有会话失效，需重新登录
func handleAuthUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeAPI(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeAPI(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	defer r.Body.Close()
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		Username        string `json:"username"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeAPI(w, http.StatusBadRequest, apiResponse{Error: "invalid JSON"})
		return
	}
	auth := getAdminAuth()
	if !auth.check(auth.Username, req.CurrentPassword) {
		writeAPI(w, http.StatusForbidden, apiResponse{Error: "当前密码错误"})
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		username = auth.Username
	}
	if len(username) < 2 || len(username) > 64 {
		writeAPI(w, http.StatusBadRequest, apiResponse{Error: "用户名长度需在 2~64 之间"})
		return
	}
	password := req.NewPassword
	if password == "" {
		password = req.CurrentPassword
	}
	if len(password) < 4 || len(password) > 128 {
		writeAPI(w, http.StatusBadRequest, apiResponse{Error: "密码长度需在 4~128 之间"})
		return
	}
	if username == auth.Username && password == req.CurrentPassword {
		writeAPI(w, http.StatusBadRequest, apiResponse{Error: "用户名和密码均未变化"})
		return
	}

	p := loadPool()
	poolMu.Lock()
	p.Admin = newAdminAuth(username, password)
	poolMu.Unlock()
	savePool()
	dropAllSessions()
	setSessionCookie(w, "", -1)
	writeAPI(w, http.StatusOK, apiResponse{Success: true, Message: "凭据已更新，请重新登录", Data: map[string]any{"username": username}})
}
