package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"

	"graphish/app"
	"graphish/db"

	"graphish/static"
	"graphish/views"

	"flag"

	"github.com/gorilla/sessions"
	"github.com/gotuna/gotuna"
)

const (
	passwordLength = 16
	charset        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}<>?,."
)

func generatePassword(length int) (string, error) {
	password := make([]byte, length)
	charsetLength := len(charset)

	for i := range password {
		randomByte := make([]byte, 1)
		_, err := rand.Read(randomByte)
		if err != nil {
			return "", err
		}
		password[i] = charset[randomByte[0]%byte(charsetLength)]
	}

	return string(password), nil
}

func main() {
	flag.String("ip", "", "IP address to allow access")
	flag.String("id", "", "Microsoft Graph API client ID")
	flag.Parse()
	if flag.Lookup("ip").Value.String() == "" || flag.Lookup("id").Value.String() == "" {
		fmt.Println("Please provide both ip and id")
		return
	}
	Db := db.ConnectDB()
	err := db.MigrateDB(Db)
	if err != nil {
		panic(err)
	}
	go db.GetAccessTokens(Db, flag.Lookup("id").Value.String())
	go db.RefreshAccessTokens(Db, flag.Lookup("id").Value.String())
	port := ":8080"
	cookieStore := sessions.NewCookieStore([]byte("B_z_vx3b-zHPszMvdxyx44BhbFzBtsGl-2-L3p68fLw"))
	cookieStore.Options.HttpOnly = true // more secure
	cookieStore.Options.MaxAge = 3600   // 1 hour
	//comment the next two line to use secure cookies
	cookieStore.Options.Secure = false                  // set to true in production with HTTPS
	cookieStore.Options.SameSite = http.SameSiteLaxMode // set to http.SameSiteStrictMode for more security
	//generate a random password for the admin user
	password, err := generatePassword(passwordLength)
	if err != nil {
		log.Fatalf("could not generate password: %v", err)
	}
	var adminUser = gotuna.InMemoryUser{
		ID:       "1",
		Name:     "sha256sum",
		Email:    "sha256sum@exploit.im",
		Password: password,
	}
	userRepository := gotuna.NewInMemoryUserRepository([]gotuna.InMemoryUser{
		adminUser,
	})

	app := app.MakeApp(app.App{
		App: gotuna.App{
			Router:         gotuna.NewMuxRouter(),
			Logger:         log.New(os.Stdout, "", 0),
			UserRepository: userRepository,
			Session:        gotuna.NewSession(cookieStore, "app_session"),
			Static:         static.EmbededStatic,
			StaticPrefix:   "",
			ViewFiles:      views.EmbededViews,
		},
	}, Db, flag.Lookup("id").Value.String(), flag.Lookup("ip").Value.String())

	fmt.Printf("Admin user created with this credentials:\n")
	fmt.Printf("Username: %s\n", adminUser.Name)
	fmt.Printf("Email: %s\n", adminUser.Email)
	fmt.Printf("Password: %s\n", password)
	fmt.Printf("starting server at http://0.0.0.0%s \n", port)

	if err := http.ListenAndServe(port, app.Router); err != nil {
		log.Fatalf("could not listen on port %s %v", port, err)
	}

}
