package main

import (
	b64 "encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type onboardinScript struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Type       string          `json:"type"`
	Location   string          `json:"location"`
	Properties json.RawMessage `json:"properties"`
}

type packages struct {
	Windows     string          `json:"onboardingPackageWindows"`
	Linux       string          `json:"onboardingPackageLinux"`
	WindowsCM   string          `json:"onboardingPackageWindowsCM"`
	Winverify   json.RawMessage `json:"windowsVerificationModel"`
	Linuxverify json.RawMessage `json:"linuxVerificationModel"`
	WinCMverify json.RawMessage `json:"windowsCMVerificationModel"`
}
type tokenResponse struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    string `json:"expires_in"`
	ExtExpiresIn string `json:"ext_expires_in"`
	ExpiresOn    string `json:"expires_on"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	AccessToken  string `json:"access_token"`
}

var tenantID string
var appID string
var secret string
var token string
var subid string
var subidlist []string
var list string

func init() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("error loading .env")
	}
	tenantID = os.Getenv("TENANTID")
	appID = os.Getenv("APPID")
	secret = os.Getenv("SECRET")
}

func main() {

	flag.StringVar(&subid, "subid", "subID", "Please set the subscription ID")
	//outPath := flag.String("path",".","Set output Path")
	flag.StringVar(&list, "csv", "0", "Set  CSV Files for multiple Tenants")
	flag.Parse()

	//  token move
	token1, err := GetToken(tenantID, appID, secret)
	if err != nil {
		log.Fatal(err)
	}
	token = token1
	readSubCsv(list)
	// check if list is filled
	if len(list) < 2 || subid != "subID"{
		//write out the package
		winpackage := parsePackage(GetOnboardingPackage(token))
		decodedwinpackage, _ := b64.StdEncoding.DecodeString(winpackage)
		os.WriteFile(tenantID+"_"+"onboarding.cmd", []byte(decodedwinpackage), 0644)
	}else if len(list) > 2 ||  subid  == "subID"{
		fmt.Println(subidlist)
		//for i := range list {
			//fmt.Print(list[i])
		//}
	}else{
		fmt.Println("did not put in any flag")
	}

}

func GetToken(tenant string, clientID string, clientSecret string) (string, error) {

	apiURL := "https://login.microsoftonline.com"
	resource := fmt.Sprintf("%s/oauth2/token", tenant)
	grantType := "client_credentials"

	data := url.Values{}
	data.Set("grant_type", grantType)
	data.Add("client_id", clientID)
	data.Add("client_secret", clientSecret)
	data.Add("resource", "https://management.azure.com")

	u, _ := url.ParseRequestURI(apiURL)
	u.Path = resource
	urlStr := u.String()

	client := &http.Client{}
	r, _ := http.NewRequest("POST", urlStr, strings.NewReader(data.Encode())) // URL-encoded payload
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var tokenResponse struct {
		TokenType    string `json:"token_type"`
		ExpiresIn    string `json:"expires_in"`
		ExtExpiresIn string `json:"ext_expires_in"`
		ExpiresOn    string `json:"expires_on"`
		NotBefore    string `json:"not_before"`
		Resource     string `json:"resource"`
		AccessToken  string `json:"access_token"`
	}
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		return "", err
	}
	return tokenResponse.AccessToken, nil
}

func GetOnboardingPackage(token string) []byte {
	baseUrl := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Security/mdeOnboardings/default?api-version=2021-10-01-preview", subid)
	bearer := "bearer " + token
	req, err := http.NewRequest("GET", baseUrl, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Authorization", bearer)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	return []byte(body)
}

func parsePackage(onpackage []byte) string {

	var oP onboardinScript
	var opS packages

	if strings.Contains(string([]byte(onpackage)), "error") {
		fmt.Println("Error occured on the backend, wait 1min and retry")
		fmt.Println(string([]byte(onpackage)))
		time.Sleep(time.Second * 60)
		return parsePackage(GetOnboardingPackage(token))
	} else {
		err := json.Unmarshal(onpackage, &oP)
		if err != nil {
			log.Fatal(err)
		}
		pack := json.Unmarshal(oP.Properties, &opS)
		if pack != nil {
			log.Fatal(pack)
		}
	}
	return string(opS.Windows)

}

func readSubCsv(list string) {
	file, err := os.Open(list)
	if err != nil {
		log.Fatal(err)
	}

	csvReader := csv.NewReader(file)
	subids, err := csvReader.ReadAll()
	if err != nil {
		log.Fatal(err)
	}
	for id := 1 ;id <= len(subids);id++ {
		subidlist = append(subidlist, subids[id-1][0])
	}
}
