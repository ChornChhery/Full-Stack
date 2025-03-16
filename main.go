package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// Connect to database
var db *sql.DB

// Initialize the database connection

func initDB() {
	var err error

	//Update these values with postgresql to connect
	conn := "host=localhost port=5432 user=postgres password=6520310203 dbname=loginwithgo sslmode=disable"

	db, err = sql.Open("postgres", conn)

	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Connect successfully to database.")
}

// Hash a password
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}

// Check password if matches
func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Handle the home page
func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/index", http.StatusSeeOther)
}

// Handle login page
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		//Check if user is already exits or logged in
		cookie, err := r.Cookie("session")
		if err == nil {
			// Cookie exists, redirect to dashboard.html
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}

		// Display login page
		tmpl, err := template.ParseFiles("index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, cookie)
	}
	if r.Method == http.MethodPost {
		// process login form
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Validate input
		if username == "" || password == "" {
			w.Write([]byte(`<div class="error-message">Username and Password are corrected</div>`))
			return
		}

		// Check if user exists
		var storedHash string
		var userID int
		err := db.QueryRow("SELECT id, password FROM users WHERE username = $1", username).Scan(&userID, &storedHash)
		if err != nil {
			if err == sql.ErrNoRows {
				w.Write([]byte(`<div class="error-message">Username or password are incorrect</div>`))
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		//Check the password
		if !checkPassword(password, storedHash) {
			w.Write([]byte(`<div class="error-message">Invalid password</div>`))
			return
		}

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    fmt.Sprintf("%d", userID),
			Path:     "/",
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
		})

		// Return success message with redirect
		w.Write([]byte(`
			<div class="success-message">Login Successfully! Redirecting...</div>
			<script>
					setTimeout(function(){
						window.location.href = "/dashboard";
					},1000);
			</script>
		`))
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// Handle Regitser page
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		//Display register page
		tmpl, err := template.ParseFiles("register.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
		return
	}
	if r.Method == http.MethodPost {
		//process register form
		username := r.FormValue("username")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm-password")

		// Validate input
		if username == "" || password == "" {
			w.Write([]byte(`<div class="error-message">All fields are required</div>`))
			return
		}
		if password != confirmPassword {
			w.Write([]byte(`<div class="error-message">Password do not match</div>`))
			return
		}

		// Check if username already exists
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = $1", username).Scan(&count)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if count > 0 {
			w.Write([]byte(`<div class="error-message">Username already exists</div>`))
			return
		}

		// Hash password
		hashedPassword, err := hashPassword(password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		//Insert new user
		_, err = db.Exec("INSERT INTO users (username,password) VALUES ($1,$2)", username, hashedPassword)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Return sucess message with redirect
		w.Write([]byte(`
			<div class="success-message">Register successful! Redirecting to Login...</div>
			<script>
				setTimeout(function(){
					window.location.href = "/index";
				},2000)
			</script>
		`))
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// Handle dashboard page
func dashboardhandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/index", http.StatusSeeOther)
		return
	}

	// Get user ID from cookie
	var userID int
	fmt.Sscanf(cookie.Value, "%d", userID)

	// Get username from database
	var username string
	err = db.QueryRow("SELECT username FROM users WHERE id = $1", userID).Scan(&username)
	if err != nil {
		if err == sql.ErrNoRows {
			// Invalid user ID, clear cookie and redirect to login
			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
			})
			http.Redirect(w, r, "/index", http.StatusSeeOther)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Display dashboard.html
	tmpl, err := template.ParseFiles("dashboard.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		Username string
	}{
		Username: username,
	}
	tmpl.Execute(w, data)
}

// Handle Logout
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	//Clear the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	//Redirect to login
	http.Redirect(w, r, "/index", http.StatusSeeOther)
}

func main() {
	//Initialize database connection
	initDB()
	fmt.Println("Hello")

	//Set up static file server
	// fs:= http.FileServer(http.Dir("static"))

	//Set up routes
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/index", loginHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/dashboard", dashboardhandler)
	http.HandleFunc("/logout", logoutHandler)

	// Start a server
	log.Fatal(http.ListenAndServe(":8080", nil))
}
