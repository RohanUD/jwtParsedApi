package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func main() {
	http.HandleFunc("/home", Home)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/refresh", Refresh)

	log.Fatal(http.ListenAndServe(":8000", nil))
}

type Userdata struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var UserdataMap = map[string]string{
	"user1": "123",
	"user2": "122",
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

var jwtKey = []byte("secret_key")

func Home(w http.ResponseWriter, r *http.Request) {
	var userdata Userdata

	err := json.NewDecoder(r.Body).Decode(&userdata)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	savedPassword, ok := UserdataMap[userdata.Username]
	if !ok || savedPassword != userdata.Password {
		w.WriteHeader(http.StatusUnauthorized)
	}

	ExpirationTime := time.Now().Add(time.Minute * 5)

	claims := &Claims{
		Username: userdata.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: ExpirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES384, claims)

	tokenStr, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "cookie1",
		Value:   tokenStr,
		Expires: ExpirationTime,
	})
}
func Login(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {

		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenStr := cookie.Value

	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

	if err != nil {

		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
	}
	w.Write([]byte(fmt.Sprintf("heeloo %s", claims.Username)))

}
func Refresh(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenStr := cookie.Value

	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

	fmt.Println(tkn)

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expirationTime := time.Now().Add(time.Minute * 5)

	claims.ExpiresAt = expirationTime.Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w,
		&http.Cookie{
			Name:    "refresh_token",
			Value:   tokenString,
			Expires: expirationTime,
		})
}
