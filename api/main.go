package handler

import (
    "context"
    "encoding/json"
    "log"
    "net/http"
    "time"

    "github.com/dgrijalva/jwt-go"
    "github.com/gorilla/mux"
    "github.com/rs/cors"
    "golang.org/x/crypto/bcrypt"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
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

func init() {
    initMongo()
}

func initMongo() {
    var err error
    client, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI))
    if err != nil {
        log.Fatal("Error connecting to MongoDB:", err)
    }
    usersCollection = client.Database("test").Collection("users")
}

// Signup, login, and protected route handler functions
func signupHandler(w http.ResponseWriter, r *http.Request) {
    var user User
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    var existingUser User
    err := usersCollection.FindOne(context.TODO(), map[string]string{"email": user.Email}).Decode(&existingUser)
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

    _, err = usersCollection.InsertOne(context.TODO(), user)
    if err != nil {
        http.Error(w, "Error creating user", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode("User created")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    var loginData Login
    if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    var existingUser User
    err := usersCollection.FindOne(context.TODO(), map[string]string{"email": loginData.Email}).Decode(&existingUser)
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
    authHeader := r.Header.Get("Authorization")
    if authHeader == "" || len(authHeader) < 7 || authHeader[:7] != "Bearer " {
        http.Error(w, "Missing or invalid token", http.StatusUnauthorized)
        return
    }
    tokenString := authHeader[7:]

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

// Exported function to handle requests, as required by Vercel
func Handler(w http.ResponseWriter, r *http.Request) {
    // Initialize router and define routes
    router := mux.NewRouter()
    router.HandleFunc("/signup", signupHandler).Methods("POST")
    router.HandleFunc("/login", loginHandler).Methods("POST")
    router.HandleFunc("/protected", protectedHandler).Methods("GET")

    // Setup CORS
    corsHandler := cors.New(cors.Options{
        AllowedOrigins: []string{"*"},
        AllowedMethods: []string{"GET", "POST"},
        AllowedHeaders: []string{"Authorization", "Content-Type"},
    }).Handler(router)

    // Serve the request through CORS handler
    corsHandler.ServeHTTP(w, r)
}
