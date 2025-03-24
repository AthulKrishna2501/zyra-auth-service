package utils

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func HandleGoogleLogin(c *gin.Context) {
	googleOAuthConfig := &oauth2.Config{
		RedirectURL:  "http://localhost:3000/auth/callback",
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		Scopes:       []string{"email", "profile"},
		Endpoint:     google.Endpoint,
	}

	url := googleOAuthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func HandleGoogleCallback(c *gin.Context, oauthClient *oauth2.Config) {
	client := &http.Client{}
	code := c.Request.URL.Query().Get("code")

	t, err := oauthClient.Exchange(context.Background(), code)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to exchange token: " + err.Error()})
		return
	}

	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		c.JSON(http.StatusExpectationFailed, gin.H{"error": "Failed to get user info" + err.Error()})
		return
	}

	req.Header.Set("Authorization", "Bearer "+t.AccessToken)

	resp, err := client.Do(req)
	if err != nil && resp == nil{
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user info"})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response"})
		return
	}

	log.Print(body)

}
