package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
)

// Generate own secret key!
var secret = []byte("**********************")

type User struct {
  Id string
  Name string
  Username string
  Password string `json:"-"`
}

func main() {
	type SignIn struct {
		Username string `json:"username"`
		Password string  `json:"password"`
	}

	loginHandler := func(w http.ResponseWriter, r *http.Request){
		var s SignIn

		// Try to decode the request body into the struct. If there is an error,
		// respond to the client with the error message and a 400 status code.
		err := json.NewDecoder(r.Body).Decode(&s)
		println(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	
		// Do something with the Person struct...
	// fmt.Fprintf(w, "Person: %+v", s)

     form := make(map[string]string)
	 form["username"]=s.Username
	 
	 form["password"]=s.Password

    username, ok := form["username"]
    if !ok {
      http.Error(w, "No username field", http.StatusBadRequest)
      return
    }
    password, ok := form["password"]
    if !ok {
      http.Error(w, "No password field", http.StatusBadRequest)
      return
    }

    // Create user if your conditions match. Below, all username and passwords are accepted.
    user := &User{
      Id: "",
      Name: "",
      Username: "",
      Password:"",
    }
    if username==user.Username && password==user.Password{
    tokenString, _ := CreateToken(user.Id, user)
    payload := make(map[string]string)
    payload["access_token"] = tokenString

    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    json.NewEncoder(w).Encode(payload)
  
	}else {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
      return
	}
}
  protectedHandler := func(w http.ResponseWriter, r *http.Request){
    claims, ok := JWTClaimsFromContext(r.Context())
	print("claims: ", ok)
    json.NewEncoder(w).Encode(claims)
  }

  indexHandler := func(w http.ResponseWriter, r *http.Request){
    fmt.Fprint(w, "Status OK")
  }

  m := mux.NewRouter()
  m.HandleFunc("/", indexHandler).Methods("GET")
  m.HandleFunc("/login", loginHandler).Methods("POST")
  protected := m.PathPrefix("/").Subrouter()
  protected.Use(AuthenticationMW)
  protected.HandleFunc("/resource",protectedHandler).Methods("GET","POST")

  log.Fatal(http.ListenAndServe(":8080", m))
}

type MyJWTClaims struct {
    *jwt.RegisteredClaims
    UserInfo interface{}
}

func CreateToken(sub string, userInfo interface{}) (string,error) {
// Get the token instance with the Signing method
token := jwt.New(jwt.GetSigningMethod("HS256"))

// Choose an expiration time. Shorter the better
exp := time.Now().Add(time.Hour*2)
// Add your claims
token.Claims = &MyJWTClaims{
    &jwt.RegisteredClaims{
// Set the exp and sub claims. sub is usually the userID
        ExpiresAt: jwt.NewNumericDate(exp),
        Subject:   sub,
    },
    userInfo,
}
// Sign the token with your secret key
val, err := token.SignedString(secret)
if err != nil {
// On error return the error
    return "", err
}
// On success return the token string
return val, nil
}

func GetClaimsFromToken(tokenString string) (jwt.MapClaims, error) {
token, err := jwt.Parse(tokenString, func(token *jwt.Token)   (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v",       token.Header["alg"])
        }
    return secret, nil
})
if err != nil {
    return nil, err
}
if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
    return claims, nil
}
return nil, err
}

func AuthenticationMW(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    auth_header := r.Header.Get("Authorization")
    if !strings.HasPrefix(auth_header, "Bearer") {
        http.Error(w, "Not Authorized", http.StatusUnauthorized)
        return
    }
    
    tokenString := strings.TrimPrefix(auth_header, "Bearer ")
    
    claims, err := GetClaimsFromToken(tokenString)
    if err != nil {
      http.Error(w, err.Error(), http.StatusUnauthorized)
      return
   }
   println(claims)
   
   // r = r.WithContext(SetJWTClaimsContext(r.Context(), claims))
    //next.ServeHTTP(w)
   
})
}

type claimskey int
var claimsKey claimskey

func SetJWTClaimsContext(ctx context.Context, claims jwt.MapClaims) context.Context {
  return context.WithValue(ctx, claimsKey, claims)
}

func JWTClaimsFromContext(ctx context.Context) (jwt.MapClaims, bool) {
  claims, ok := ctx.Value(claimsKey).(jwt.MapClaims)
  return claims, ok
}