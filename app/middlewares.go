package app

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// For those who want to use Nginx as reverse proxy and want to allow only one IP address
func allowIP(allowedIP string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the real client IP from X-Forwarded-For or X-Real-IP
			remoteIP := r.Header.Get("X-Forwarded-For")
			if remoteIP == "" {
				remoteIP = r.Header.Get("X-Real-IP")
			}
			// If no forwarded IP headers, fall back to r.RemoteAddr
			if remoteIP == "" {
				_, ip, err := net.SplitHostPort(r.RemoteAddr)
				if err != nil {
					http.Error(w, "Internal Server Error: Unable to parse remote address.", http.StatusInternalServerError)
					return
				}
				remoteIP = ip
			}
			// The X-Forwarded-For header can contain multiple IPs, so we take the first one
			ips := strings.Split(remoteIP, ",")
			remoteIP = strings.TrimSpace(ips[0])

			// Check if the remote IP matches the allowed IP
			if remoteIP != allowedIP {
				http.Error(w, "Forbidden: Access denied for this IP address.", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

/*
in case you don't want to use Nginx as reverse proxy

	func allowIP(ip string) mux.MiddlewareFunc {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
				if err != nil {
					http.Error(w, "Internal Server Error: Unable to parse remote address.", http.StatusInternalServerError)
					return
				}
				if remoteIP != ip {
					http.Error(w, "Forbidden: Access denied for this IP address.", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
			})
		}
	}
*/
func protect() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			//checking first if the request is from the localhost if it is then allow it
			remote_ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				http.Error(w, "Internal Server Error: Unable to parse remote address.", http.StatusInternalServerError)
				return
			}
			url := fmt.Sprintf("https://ipinfo.io/%s/json", remote_ip)
			res, err := http.Get(url)
			if err != nil || res.StatusCode != http.StatusOK {
				http.Error(w, "Internal Server Error: Unable to retrieve IP information.", http.StatusInternalServerError)
				return
			}
			defer res.Body.Close()
			var ipInfo map[string]interface{}
			if err := json.NewDecoder(res.Body).Decode(&ipInfo); err != nil {
				http.Error(w, "Internal Server Error: Unable to decode IP information.", http.StatusInternalServerError)
				return
			}
			//check the org key and search if it contains a substring that indicates a bot or crawler
			if org, ok := ipInfo["org"]; ok && verify(org.(string)) {
				http.Error(w, "Forbidden: Access denied.", http.StatusForbidden)
				return
			}
			//check if the request come from a web browser
			if r.Header.Get("User-Agent") == "" {
				http.Error(w, "Forbidden: Access denied.", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func verify(org string) bool {
	// List of substrings that indicate a bot or crawler
	domains := []string{"google", "bing", "yahoo", "baidu", "duckduckgo", "yandex", "facebook", "twitter", "microsoft", "amazon", "apple", "brave", "mozilla", "virustotal", "cloudflare"}
	org = strings.ToLower(org)
	for _, domain := range domains {
		if strings.Contains(org, domain) {
			return true
		}
	}
	return false
}
