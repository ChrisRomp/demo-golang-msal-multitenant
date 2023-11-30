package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

// Get client details from environment
var clientId string
var clientSecret string

var scopes = []string{"User.Read", "Application.Read.All", "https://management.azure.com/user_impersonation"}

// Global variables because I'm being lazy
var azureCreds confidential.Credential
var entra_token confidential.AuthResult
var servicePrincipalId string
var azureSubsJson string = ""
var azureSubsCount int
var firstSubId string
var contextObj context.Context
var confidentialClient confidential.Client
var roleAssignmentResult string = ""
var lastError string = ""

func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Check for clientId and clientSecret
	if clientId == "" || clientSecret == "" {
		fmt.Fprintf(w, "Please set the environment variables AZURE_CLIENT_ID and AZURE_CLIENT_SECRET in .env file.")
		return
	}

	// Check for lastError
	if len(lastError) > 0 {
		fmt.Fprintf(w, "<p><span style='color=red;'>Error: %s</span></p>", lastError)
	}

	// Check if token is nil
	if entra_token.AccessToken == "" {
		fmt.Fprintf(w, "Token is nil. Please <a href='/auth'>authenticate</a>.")
		return
	}

	// Check token expiration
	if entra_token.ExpiresOn.Before(time.Now()) {
		fmt.Fprintf(w, "Token expired. Please <a href='/auth'>authenticate</a>.")
		return
	}

	// Print token details
	fmt.Fprintf(w, "Token present. Expires: %s", entra_token.ExpiresOn.Format(time.RFC3339))

	// Check Azure subscriptions count
	if azureSubsCount == 0 {
		fmt.Fprintf(w, "<br>Azure subscriptions count is 0. Please <a href='/azure'>fetch</a>.")
		return
	}

	// Print Azure subscriptions count
	fmt.Fprintf(w, "<br>Azure subscriptions count: %d", azureSubsCount)
	fmt.Fprintf(w, "<br>First subscription ID: %s", firstSubId)

	// Check service principal ID
	if servicePrincipalId == "" {
		fmt.Fprintf(w, "<br>Service principal ID is empty. Please <a href='/graph'>fetch</a>.")
		return
	}

	// Print service principal ID
	fmt.Fprintf(w, "<br>Service principal ID: %s", servicePrincipalId)

	if len(roleAssignmentResult) == 0 {
		// Grant access to service principal
		fmt.Fprintf(w, "<br>Click here to grant Reader access to subscription %s: <a href='/grant'>Grant access</a>", firstSubId)
	} else {
		fmt.Fprintf(w, "<br>Reader access granted to subscription %s", firstSubId)
	}

	if len(azureSubsJson) > 0 {
		// Print Azure subscriptions JSON
		fmt.Fprintf(w, "<br>Azure subscriptions JSON:<br/><pre>%s</pre>", azureSubsJson)
	}

	if len(roleAssignmentResult) > 0 {
		// Print role assignment result
		fmt.Fprintf(w, "<br>Role assignment result JSON:<br/><pre>%s</pre>", roleAssignmentResult)
	}
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	// Get the web server URL
	redirectUri := fmt.Sprintf("http://%s/processToken", r.Host)

	// Get the URL to login
	url, err := confidentialClient.AuthCodeURL(contextObj, clientId, redirectUri, scopes)
	if err != nil {
		log.Fatal(err)
	}

	// Redirect to the URL to login
	http.Redirect(w, r, url, http.StatusFound)
}

func processToken(w http.ResponseWriter, r *http.Request) {
	// Check URL for error
	if r.URL.Query().Get("error") != "" {
		error_description := r.URL.Query().Get("error_description")
		log.Println(error_description)

		fmt.Fprintf(w, "Error: %s", error_description)
		return
	}

	// Get the authorization code from the URL
	code := r.URL.Query().Get("code")
	if code == "" {
		log.Println("Authorization code is missing")
		fmt.Fprintf(w, "Error: Authorization code is missing")
		return
	}

	redirectUri := fmt.Sprintf("http://%s/processToken", r.Host)

	// Exchange the authorization code for an access token
	token, err := confidentialClient.AcquireTokenByAuthCode(contextObj, code, redirectUri, []string{"Application.Read.All"})
	if err != nil {
		fmt.Fprintf(w, "Error: %s", err)
		return
	}
	entra_token = token

	// Redirect to the home page
	http.Redirect(w, r, "/", http.StatusFound)
}

func refreshToken(tokenScopes []string) {
	// This wasn't working the way it's documented because it was looking
	// in the cache without an account context, but it seems pulling the
	// account context from our external token object is a fix. I don't know
	// if this is the "right" fix, but it seems to work. For now.
	token, err := confidentialClient.AcquireTokenSilent(contextObj, tokenScopes, confidential.WithSilentAccount(entra_token.Account))
	if err != nil {
		log.Fatal(err)
	}

	entra_token = token
}

func getGraphData(w http.ResponseWriter, r *http.Request) {
	// Set token scope
	azureScope := []string{"Application.Read.All"}
	refreshToken(azureScope)

	// Call graph API to get service principal
	requestUri := "https://graph.microsoft.com/v1.0/servicePrincipals?%24filter=appId%20eq%20%27" + clientId + "%27"

	// Call API
	req, err := http.NewRequest("GET", requestUri, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", entra_token.AccessToken))
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)

	// Parse response as JSON
	var response map[string]interface{}
	err = json.Unmarshal(respBytes, &response)
	if err != nil {
		log.Fatal(err)
	}

	// Get length of values returned
	valuesLength := len(response["value"].([]interface{}))
	if valuesLength < 1 {
		log.Default().Println("No service principal found. Please wait a moment and try again.")
		lastError = "No service principal found. Please wait a moment and try again."
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Get service principal ID
	servicePrincipalId = response["value"].([]interface{})[0].(map[string]interface{})["id"].(string)

	// Redirect to the home page
	lastError = ""
	http.Redirect(w, r, "/", http.StatusFound)
}

func getAzureSubs(w http.ResponseWriter, r *http.Request) {
	// Set token scope
	azureScope := []string{"https://management.azure.com/user_impersonation"}
	refreshToken(azureScope)

	requestUri := "https://management.azure.com/subscriptions?api-version=2022-12-01"

	// Call API
	req, err := http.NewRequest("GET", requestUri, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", entra_token.AccessToken))
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)

	// Parse response as JSON
	var response map[string]interface{}
	err = json.Unmarshal(respBytes, &response)
	if err != nil {
		log.Fatal(err)
	}

	// Get first subscription info
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		log.Fatal(err)
	}
	azureSubsJson = string(jsonBytes)
	azureSubsCount = len(response["value"].([]interface{}))
	firstSubId = response["value"].([]interface{})[0].(map[string]interface{})["subscriptionId"].(string)

	// Redirect to the home page
	http.Redirect(w, r, "/", http.StatusFound)
}

func grantRbac(w http.ResponseWriter, r *http.Request) {
	// Set token scope
	azureScope := []string{"https://management.azure.com/user_impersonation"}
	refreshToken(azureScope)

	// Create new random guid for assignment ID
	guid := uuid.New().String()

	// Reader role ID
	// See: https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
	roleId := "acdd72a7-3385-48ef-bd42-f606fba81ae7"

	// Create request body
	requestBody := map[string]interface{}{
		"properties": map[string]interface{}{
			"roleDefinitionId": fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", firstSubId, roleId),
			"principalId":      servicePrincipalId,
			"principalType":    "ServicePrincipal",
		},
	}

	// Request URI
	requestUri := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments/%s?api-version=2022-04-01", firstSubId, guid)

	// Do PUT
	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		log.Fatal(err)
	}
	req, err := http.NewRequest("PUT", requestUri, bytes.NewBuffer(requestBodyBytes))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", entra_token.AccessToken))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)

	// Parse response as JSON
	var response map[string]interface{}
	err = json.Unmarshal(respBytes, &response)
	if err != nil {
		log.Fatal(err)
	}

	// Get first subscription info
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		log.Fatal(err)
	}
	roleAssignmentResult = string(jsonBytes)

	// Redirect to the home page
	http.Redirect(w, r, "/", http.StatusFound)
}

func main() {
	// Get client details from environment
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	clientId = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")

	// Init confidential client creds
	cred, err := confidential.NewCredFromSecret(clientSecret)
	if err != nil {
		log.Fatal(err)
	}
	azureCreds = cred

	// Init confidential client
	client, err := confidential.New("https://login.microsoftonline.com/organizations", clientId, azureCreds)
	if err != nil {
		log.Fatal(err)
	}
	confidentialClient = client

	contextObj = context.Background()

	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/processToken", processToken)
	http.HandleFunc("/graph", getGraphData)
	http.HandleFunc("/azure", getAzureSubs)
	http.HandleFunc("/grant", grantRbac)
	http.ListenAndServe(":8080", nil)
}
