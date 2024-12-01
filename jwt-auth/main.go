package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var secret = "shkfjshfkjsfgerufyegurfgfuefwjhfbwhfwegfhfvw"

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var users = map[string]User{
	"john": {
		Username: "john",
		Password: "$2a$10$K1D2qYuDRbZyAopFVgyMtezXzWY4d87aZ0uwbl48NnzJwHowWfrWu", // hashed "password123"
	},
}

// Claims extends standard JWT claims
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func GenerateToken(user User) (string, error) {
	expTime := time.Now().Add(24 * time.Hour)

	claims := &Claims{
		Username: "john",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		fmt.Println("error signing token")
		return "", err
	}

	fmt.Println("token :", tokenString)
	return tokenString, nil
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Login Handler started...")

	var req User
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		fmt.Println("error decoding body", err)
		return
	}

	user, exists := users[req.Username]
	if !exists {
		fmt.Println("user doesn't exist")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		fmt.Println("invalid password", err)
		return
	}

	tokenString, err := GenerateToken(user)
	if err == nil {
		json.NewEncoder(w).Encode(map[string]string{
			"token": tokenString,
		})
	}
}

func ValidateToken(tokenString string) (*Claims, error){

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(secret), nil
	})

	if err != nil {
		fmt.Println("inavlid token")
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("inavlid token")
}

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Middleware starting...")
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			fmt.Println("Authorization cannot be empty")
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			fmt.Println("invalid authorization header")
		}

		claims, err := ValidateToken(parts[1])
		if err != nil {
			return
		}
		fmt.Println(claims)

		next.ServeHTTP(w, r)
		fmt.Println("Middleware completed...")
	})
}

func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("protected handler...")
}

func main() {
	fmt.Println("Starting server...")
	r := chi.NewRouter()

	r.Post("/login", LoginHandler)

	r.Route("/protected", func(r chi.Router) {
		r.Use(JWTMiddleware)
		r.Get("/", ProtectedHandler)
	})


	if err := http.ListenAndServe(":8080", r); err != nil {
		fmt.Println("error starting server")
	}
}
