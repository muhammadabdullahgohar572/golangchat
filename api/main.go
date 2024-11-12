package handler

import (
    "encoding/json"
    "net/http"
    "time"

    "github.com/dgrijalva/jwt-go"
    "github.com/gorilla/mux"
    "golang.org/x/crypto/bcrypt"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    "github.com/rs/cors"
)

var jwtSecret = []byte("abdullah55")
var mongoURI = "mongodb+srv://Abdullah1:Abdullah1@cluster0.agxpb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

// User and Login structs
type User struct {
    Username    string `json:"username"`
    Password    string `json:"password"`
    Email       string `json:"email"`
    Gender      string `json:"gender"`
    CompanyName string `json:"company_name"`
}

type Login struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

type Claims struct {
    Email string `json:"email"`
    jwt.StandardClaims
}

var client *mongo.Client
var usersCollection *mongo.Collection

func initMongo() {
    var err error
    client, err = mongo.Connect(nil, options.Client().ApplyURI(mongoURI))
    if err != nil {
        panic(err)
    }
    usersCollection = client.Database("test").Collection("users")
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
    var user User
    _ = json.NewDecoder(r.Body).Decode(&user)

    var existingUser User
    err := usersCollection.FindOne(nil, map[string]string{"email": user.Email}).Decode(&existingUser)
    if err == nil {
        http.Error(w, "Email already exists", http.StatusConflict)
        return
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Error hashing password", http.StatusInternalServerError)
        return
    }
    user.Password = string(hashedPassword)

    _, err = usersCollection.InsertOne(nil, user)
    if err != nil {
        http.Error(w, "Error creating user", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode("User created")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    var loginData Login
    _ = json.NewDecoder(r.Body).Decode(&loginData)

    var existingUser User
    err := usersCollection.FindOne(nil, map[string]string{"email": loginData.Email}).Decode(&existingUser)
    if err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    err = bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(loginData.Password))
    if err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    expirationTime := time.Now().Add(24 * time.Hour)
    claims := &Claims{
        Email: loginData.Email,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtSecret)
    if err != nil {
        http.Error(w, "Could not create token", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
    tokenString := r.Header.Get("Authorization")
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        return jwtSecret, nil
    })

    if err != nil || !token.Valid {
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode("Welcome to the protected route")
}

func Handler(w http.ResponseWriter, r *http.Request) {
    initMongo()

    corsHandler := cors.New(cors.Options{
        AllowedOrigins: []string{"*"},
    }).Handler

    router := mux.NewRouter()
    router.HandleFunc("/signup", signupHandler).Methods("POST")
    router.HandleFunc("/login", loginHandler).Methods("POST")
    router.HandleFunc("/protected", protectedHandler).Methods("GET")

    corsHandler(router).ServeHTTP(w, r)
}
