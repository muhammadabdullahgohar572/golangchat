package handler

import (
    "encoding/json"
    "fmt"
    "net/http"
    "time"

    "github.com/dgrijalva/jwt-go"
    "github.com/gorilla/mux"
    "golang.org/x/crypto/bcrypt"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
)

// Global variables for JWT and MongoDB
var jwtSecret = []byte("abdullah55")
var mongoURI = "mongodb+srv://Abdullah1:Abdullah1@cluster0.agxpb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

// User structure for signup
type User struct {
    Username    string `json:"username"`
    Password    string `json:"password"`
    Email       string `json:"email"`
    Gender      string `json:"gender"`
    CompanyName string `json:"company_name"`
}

// Login structure
type Login struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

// Struct for JWT token
type Claims struct {
    Email string `json:"email"`
    jwt.StandardClaims
}

// MongoDB client initialization
var client *mongo.Client
var usersCollection *mongo.Collection

// Function to initialize MongoDB
func initMongo() {
    var err error
    client, err = mongo.Connect(nil, options.Client().ApplyURI(mongoURI))
    if err != nil {
        fmt.Println("Error connecting to MongoDB:", err)
    }
    usersCollection = client.Database("test").Collection("users")
}

// Signup handler
func signupHandler(w http.ResponseWriter, r *http.Request) {
    var user User
    _ = json.NewDecoder(r.Body).Decode(&user)

    // Check if email already exists
    var existingUser User
    err := usersCollection.FindOne(nil, map[string]string{"email": user.Email}).Decode(&existingUser)
    if err == nil {
        http.Error(w, "Email already exists", http.StatusConflict)
        return
    }

    // Hash password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Error hashing password", http.StatusInternalServerError)
        return
    }

    user.Password = string(hashedPassword)

    // Insert user into MongoDB
    _, err = usersCollection.InsertOne(nil, user)
    if err != nil {
        http.Error(w, "Error creating user", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode("User created")
}

// Login handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
    var loginData Login
    _ = json.NewDecoder(r.Body).Decode(&loginData)

    // Check if the user exists by email
    var existingUser User
    err := usersCollection.FindOne(nil, map[string]string{"email": loginData.Email}).Decode(&existingUser)
    if err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Check password
    err = bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(loginData.Password))
    if err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Generate JWT token
    expirationTime := time.Now().Add(24 * time.Hour)
    claims := &Claims{
        Email: loginData.Email,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: jwt.At(expirationTime),
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

// Protected route (example)
func protectedHandler(w http.ResponseWriter, r *http.Request) {
    tokenString := r.Header.Get("Authorization")

    // Parse JWT token
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

// Handler function for Vercel
func Handler(w http.ResponseWriter, r *http.Request) {
    // Initialize MongoDB
    initMongo()

    // Set up CORS
    corsHandler := cors.New(cors.Options{
        AllowedOrigins: []string{"*"},
    }).Handler

    r := mux.NewRouter()
    r.HandleFunc("/signup", signupHandler).Methods("POST")
    r.HandleFunc("/login", loginHandler).Methods("POST")
    r.HandleFunc("/protected", protectedHandler).Methods("GET")

    // Start the server with CORS support
    http.ListenAndServe(":8080", corsHandler(r))
}
