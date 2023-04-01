package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jws"
)

// struct for app
type DeveloperApp struct {
	App []AppId
}

type AppId struct {
	AppId string
}

// struct for details for app
type DeveloperAppDetails struct {
	Name        string
	Credentials []Credentials
}

// struct for api key pair
type Credentials struct {
	ApiProducts    []ApiProducts
	ConsumerKey    string
	ConsumerSecret string
	IssuedAt       string
}

type ApiProducts struct {
	ApiProduct string
	Status     string
}

// struct for vault byte response
type VaultByteResponse struct {
	Request_Id string
	Data       VaultByteResponseData
}

// struct for byte generation response data
type VaultByteResponseData struct {
	Random_Bytes string
}

// struct for vault byte response
type VaultAuthResponse struct {
	Request_Id string
	Auth       VaultAuthResponseData
}

type VaultAuthResponseData struct {
	Client_Token string
	Accessor     string
}

// struct for vault data response
type VaultAccessResponse struct {
	Data VaultAccessResponseData
}

type VaultAccessResponseData struct {
	Data map[string]string
}

// grab vault cert information from key vault
func grabVaultCert(vaultURI string) (string, string, string) {

	// Create a credential using the NewDefaultAzureCredential type.
	cred, err := azidentity.NewDefaultAzureCredential(nil)

	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}

	// Establish a connection to the Key Vault client
	client, err := azsecrets.NewClient(vaultURI, cred, nil)

	// Get a secret. An empty string version gets the latest version of the secret.
	version := ""
	resp, err := client.GetSecret(context.TODO(), "vault-cer", version, nil)
	if err != nil {
		log.Fatalf("failed to get the secret: %v", err)
	}

	vaultCer := *resp.Value

	resp, err = client.GetSecret(context.TODO(), "vault-ca", version, nil)
	if err != nil {
		log.Fatalf("failed to get the secret: %v", err)
	}

	vaultCA := *resp.Value

	resp, err = client.GetSecret(context.TODO(), "vault-cer-key", version, nil)
	if err != nil {
		log.Fatalf("failed to get the secret: %v", err)
	}

	vaultKey := *resp.Value

	return vaultCer, vaultCA, vaultKey
}

// function to authenticate to Hashicorp Vault using SSL/TLS
func vaultAuth(role string) string {

	// get certificates and temporary store
	vaultCer, vaultCA, vaultKey := grabVaultCert("https://{KEYVAULT}.vault.azure.net")

	cert := []byte(vaultCer)

	err := os.WriteFile("/tmp/cert.pem", cert, 0644)

	if err != nil {
		log.Fatal(err)
	}

	cacert := []byte(vaultCA)

	err = os.WriteFile("/tmp/ca.pem", cacert, 0644)

	if err != nil {
		log.Fatal(err)
	}

	key := []byte(vaultKey)

	err = os.WriteFile("/tmp/key.pem", key, 0644)

	if err != nil {
		log.Fatal(err)
	}

	// vault login
	caCert, _ := ioutil.ReadFile("/tmp/ca.pem")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsCert, err := tls.LoadX509KeyPair("/tmp/cert.pem", "/tmp/key.pem")

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				Certificates:       []tls.Certificate{tlsCert},
				InsecureSkipVerify: true,
			},
		},
	}

	url := "https://{VAULTURL}/v1/auth/cert/login"

	data := map[string]string{
		"name": role,
	}

	body, err := json.Marshal(data)

	// exit if error is found
	if err != nil {
		return "error"
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)

	if err != nil {
		os.Remove("/tmp/cert.pem")
		os.Remove("/tmp/ca.pem")
		os.Remove("/tmp/key.pem")
		return "error"
	}

	// cleanup
	os.Remove("/tmp/cert.pem")
	os.Remove("/tmp/ca.pem")
	os.Remove("/tmp/key.pem")

	respbody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	var responseObject VaultAuthResponse
	json.Unmarshal(respbody, &responseObject)

	return responseObject.Auth.Client_Token
}

// grab apigee SA from Hashicorp Vault
func grabApigeeSA(secretPath string) string {

	authKey := vaultAuth("key-rotation-function")
	url := fmt.Sprintf("https://{VAULTURL}/v1/%s", secretPath)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	req, err := http.NewRequest("GET", url, nil)

	// exit if error is found
	if err != nil {
		return "error making get request"
	}

	req.Header.Add("X-Vault-Token", authKey)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)

	// exit if error is found
	if err != nil {
		return "error making get request"
	}

	respbody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	var responseObject VaultAccessResponse

	json.Unmarshal(respbody, &responseObject)

	return responseObject.Data.Data["secret"]
}

// generateJWT creates a signed JSON Web Token using a Google API Service Account.
func generateJWT(saKeyfile, saEmail, audience string, expiryLength int64) (string, error) {
	now := time.Now().Unix()

	// Build the JWT payload.
	jwt := &jws.ClaimSet{
		Iat: now,
		// expires after 'expiryLength' seconds.
		Exp: now + expiryLength,
		// Iss must match 'issuer' in the security configuration in your
		// swagger spec (e.g. service account email). It can be any string.
		Iss: saEmail,
		// Aud must be either your Endpoints service name, or match the value
		// specified as the 'x-google-audience' in the OpenAPI document.
		Aud: audience,
		// Sub and Email should match the service account's email address.
		Sub:           saEmail,
		PrivateClaims: map[string]interface{}{"email": saEmail},
		Scope:         "https://www.googleapis.com/auth/cloud-platform",
	}
	jwsHeader := &jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
	}

	// Extract the RSA private key from the service account keyfile.
	sa, err := ioutil.ReadFile(saKeyfile)
	if err != nil {
		return "", fmt.Errorf("Could not read service account file: %v", err)
	}
	conf, err := google.JWTConfigFromJSON(sa)
	if err != nil {
		return "", fmt.Errorf("Could not parse service account JSON: %v", err)
	}
	block, _ := pem.Decode(conf.PrivateKey)
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("private key parse error: %v", err)
	}
	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	// Sign the JWT with the service account's private key.
	if !ok {
		return "", errors.New("private key failed rsa.PrivateKey type assertion")
	}
	return jws.Encode(jwsHeader, jwt, rsaKey)
}

// Make OAuth2 Authentication request to Apigee
func apigeeAuth(url string) (interface{}, error) {

	// grab apigee sa
	saPath := "/tmp/apigee-sa.json"
	sa := grabApigeeSA("apigee-rotation/data/apigee-sa")
	account := []byte(sa)
	err := os.WriteFile(saPath, account, 0644)

	if err != nil {
		log.Fatal(err)
	}

	// generate jwt for oauth request
	signedJWT, err := generateJWT(saPath, "{SERVICEACCOUNT}", "https://oauth2.googleapis.com/token", 3600)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// exit if error is found
	if err != nil {
		return "error", err
	}

	// mmake oauth request
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %v", err)
	}

	q := req.URL.Query()
	q.Add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	q.Add("assertion", signedJWT)
	req.URL.RawQuery = q.Encode()
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	response, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %v", err)
	}
	defer response.Body.Close()

	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("failed to parse HTTP response: %v", err)
	}

	var oauthResponse map[string]interface{}
	err = json.Unmarshal(responseData, &oauthResponse)

	if err != nil {
		return "", fmt.Errorf("failed to parse HTTP response: %v", err)
	}

	return oauthResponse["access_token"], nil
}

// function to return a slice of apps
func getDeveloperApps(org string, dev string) ([]string, error) {

	var responseObject DeveloperApp

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	authKey, err := apigeeAuth("https://oauth2.googleapis.com/token")

	if err != nil {
		log.Fatal(err)
	}

	authKeyStr := fmt.Sprint(authKey)

	url := fmt.Sprintf("https://apigee.googleapis.com/v1/organizations/%s/developers/%s/apps", org, dev)
	req, err := http.NewRequest("GET", url, nil)

	// exit if error is found
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	bearer := "Bearer " + authKeyStr
	req.Header.Add("Authorization", bearer)
	resp, err := client.Do(req)

	// exit if error is found
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	err = json.NewDecoder(resp.Body).Decode(&responseObject)

	// exit if error is found
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	apps := []string{}

	for _, p := range responseObject.App {
		apps = append(apps, p.AppId)
	}

	return apps, nil
}

// // function to get app keys
func getAppKeys(org string, dev string, app string) (DeveloperAppDetails, error) {
	url := ""
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	var responseObject DeveloperAppDetails
	authKey, err := apigeeAuth("https://oauth2.googleapis.com/token")

	if err != nil {
		log.Fatal(err)
	}

	authKeyStr := fmt.Sprint(authKey)

	url = fmt.Sprintf("https://apigee.googleapis.com/v1/organizations/%s/developers/%s/apps/%s", org, dev, app)

	req, err := http.NewRequest("GET", url, nil)

	// exit if error is found
	if err != nil {
		return responseObject, fmt.Errorf("%s", err)
	}

	bearer := "Bearer " + authKeyStr
	req.Header.Add("Authorization", bearer)
	resp, err := client.Do(req)

	// exit if error is found
	if err != nil {
		return responseObject, fmt.Errorf("%s", err)
	}

	err = json.NewDecoder(resp.Body).Decode(&responseObject)

	// exit if error is found
	if err != nil {
		return responseObject, fmt.Errorf("%s", err)
	}

	return responseObject, nil
}

// function to make API call to Vault to generate random key value
func generateRandomKey() (VaultByteResponse, error) {

	var responseObject VaultByteResponse

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
	}

	// make api call to generate random key
	authKey := vaultAuth("key-rotation-function")
	url := "https://{VAULTURL}/v1/sys/tools/random/32"

	body := []byte(`{"format": "hex"}`)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	req.Header.Add("X-Vault-Token", authKey)

	// exit if error is found
	if err != nil {
		return responseObject, fmt.Errorf("%s", err)
	}

	resp, err := client.Do(req)

	// exit if error is found
	if err != nil {
		return responseObject, fmt.Errorf("%s", err)
	}

	err = json.NewDecoder(resp.Body).Decode(&responseObject)

	// exit if error is found
	if err != nil {
		return responseObject, fmt.Errorf("%s", err)
	}

	return responseObject, nil
}

// function to make API call to Apigee to create new key in an app
func createNewAppKey(org string, dev string, app string, secret string) (Credentials, error) {

	var responseObject Credentials
	currentTime := time.Now().Format("2006-01-02_15-04")

	// update apigee secret key values
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	authKey, err := apigeeAuth("https://oauth2.googleapis.com/token")

	if err != nil {
		log.Fatal(err)
	}

	authKeyStr := fmt.Sprint(authKey)

	url := fmt.Sprintf("https://apigee.googleapis.com/v1/organizations/%s/developers/%s/apps/%s/keys/create", org, dev, app)

	data := map[string]string{
		"consumerKey":    currentTime,
		"consumerSecret": secret,
	}

	body, err := json.Marshal(data)
	// exit if error is found
	if err != nil {
		return responseObject, fmt.Errorf("%s", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))

	// exit if error is found
	if err != nil {
		return responseObject, fmt.Errorf("%s", err)
	}

	bearer := "Bearer " + authKeyStr
	req.Header.Add("Authorization", bearer)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)

	// exit if error is found
	if err != nil {
		return responseObject, fmt.Errorf("%s", err)
	}

	err = json.NewDecoder(resp.Body).Decode(&responseObject)

	// exit if error is found
	if err != nil {
		return responseObject, fmt.Errorf("%s", err)
	}

	return responseObject, nil
}

// function to make API call to Apigee to asscociate secret key with a product
func associateAppKey(org string, dev string, app string, keyName string, products map[string]bool) (string, error) {

	var responseObject Credentials

	productArray := []string{}

	for key := range products {
		productArray = append(productArray, key)
	}

	// update apigee secret key values
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	authKey, err := apigeeAuth("https://oauth2.googleapis.com/token")

	if err != nil {
		log.Fatal(err)
	}

	authKeyStr := fmt.Sprint(authKey)

	url := fmt.Sprintf("https://apigee.googleapis.com/v1/organizations/%s/developers/%s/apps/%s/keys/%s", org, dev, app, keyName)

	data := map[string]interface{}{
		"apiProducts": productArray,
	}

	body, err := json.Marshal(data)

	// exit if error is found
	if err != nil {
		return "", fmt.Errorf("%s", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))

	// exit if error is found
	if err != nil {
		return "", fmt.Errorf("%s", err)
	}

	bearer := "Bearer " + authKeyStr
	req.Header.Add("Authorization", bearer)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)

	// exit if error is found
	if err != nil {
		return "", fmt.Errorf("%s", err)
	}

	err = json.NewDecoder(resp.Body).Decode(&responseObject)

	successMsg := fmt.Sprintf("%s was associated with products %v", keyName, productArray)

	return successMsg, nil
}

func approveProducts(org string, dev string, app string, keyName string, products map[string]bool) (string, error) {

	productArray := []string{}

	for key := range products {
		productArray = append(productArray, key)
	}

	// update apigee secret key values
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	authKey, err := apigeeAuth("https://oauth2.googleapis.com/token")

	if err != nil {
		log.Fatal(err)
	}

	authKeyStr := fmt.Sprint(authKey)

	for _, product := range productArray {
		url := fmt.Sprintf("https://apigee.googleapis.com/v1/organizations/%s/developers/%s/apps/%s/keys/%s/apiproducts/%s?action=approve", org, dev, app, keyName, product)

		data := map[string]interface{}{}

		body, err := json.Marshal(data)

		// exit if error is found
		if err != nil {
			return "", fmt.Errorf("%s", err)
		}

		req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))

		// exit if error is found
		if err != nil {
			return "", fmt.Errorf("%s", err)
		}

		bearer := "Bearer " + authKeyStr
		req.Header.Add("Authorization", bearer)
		req.Header.Add("Content-Type", "application/json")

		resp, err := client.Do(req)

		// exit if error is found
		if err != nil {
			return "", fmt.Errorf("%s", err)
		}

		defer resp.Body.Close()
	}
	successMsg := fmt.Sprintf("Products approved for %s", keyName)

	return successMsg, nil
}

func keyRotation(org string, dev string, app string) (string, error) {
	// get app keys in app
	appKeys, err := getAppKeys(org, dev, app)
	if err != nil {
		fmt.Println(err)
		return "error", err
	}

	// perform key rotation

	// generate random key value from Hashicorp Vault
	randomKey, err := generateRandomKey()
	if err != nil {
		fmt.Println(err)
		return "error", err
	}

	// create new app key
	newKey, err := createNewAppKey(org, dev, app, randomKey.Data.Random_Bytes)
	if err != nil {
		fmt.Println(err)
		return "error", err
	}

	// initialize empty map to store products to associate key with
	products := make(map[string]bool)

	// iterate through credentials in app
	for _, appKey := range appKeys.Credentials {

		// check if existing credential is used in a product
		if len(appKey.ApiProducts) == 0 {
			continue
		} else {
			// grab list of products associated with app and add to products map
			for _, value := range appKey.ApiProducts {
				if products[value.ApiProduct] {
					continue
				} else {
					products[value.ApiProduct] = true
				}
			}
		}
	}

	// assign key to existing products
	success, err := associateAppKey(org, dev, app, newKey.ConsumerKey, products)

	if err != nil {
		fmt.Println(err)
		return "error", err
	} else {
		fmt.Println(success)
	}

	// approve products
	success, err = approveProducts(org, dev, app, newKey.ConsumerKey, products)

	if err != nil {
		fmt.Println(err)
		return "error", err
	} else {
		fmt.Println(success)
	}

	return fmt.Sprintf("key rotation for %s successful", app), nil
}

// main function
func main() {
	org := "{ORG}"
	dev := "{DEVUSER}"

	apps, err := getDeveloperApps(org, dev)

	fmt.Println(apps)

	if err != nil {
		fmt.Println(err)
	}

	for _, app := range apps {
		go keyRotation(org, dev, app)
	}
}
