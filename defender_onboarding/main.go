package main

import (
	b64 "encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)
type onboardinScript struct{
		ID          string  `json:"id"`
		Name        string  `json:"name"`
		Type        string  `json:"type"`
		Location    string  `json:"location"`
		Properties  json.RawMessage  `json:"properties"`
	}

type packages struct{
	Windows    string  `json:"onboardingPackageWindows"`
	Linux      string  `json:"onboardingPackageLinux"`
	WindowsCM  string  `json:"onboardingPackageWindowsCM"`
	Winverify  json.RawMessage `json:"windowsVerificationModel"`
	Linuxverify  json.RawMessage `json:"linuxVerificationModel"`
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


var tenantID string = ""
var appID string = ""
var secret string = ""


func main(){

	tenant := flag.String("test","test","Set Tenant ID like XXX")
	outPath := flag.String("path","path","Set output Path")
	singleRun := flag.Bool("singleRun",false,"set false or true")

	fmt.Print(tenant,outPath,singleRun)		

	token,err := GetToken(tenantID,appID,secret)
	if err != nil{
		log.Fatal(err)
	}
	winpackage := parsePackage(GetOnboardingPackage(token))
	decodedwinpackage,_:= b64.StdEncoding.DecodeString(winpackage)
	os.WriteFile("onboarding.cmd",[]byte(decodedwinpackage),0644)
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


func GetOnboardingPackage(token string) []byte{
	baseUrl := "https://management.azure.com/subscriptions/[TENANTID]/providers/Microsoft.Security/mdeOnboardings/default?api-version=2021-10-01-preview" 
	bearer := "bearer " + token
	req,err := http.NewRequest("GET",baseUrl,nil)
	if err != nil{
		log.Fatal(err)
	}
	req.Header.Add("Authorization" ,bearer)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil{
		log.Fatal(err)
	}
	return []byte(body)
	}

func parsePackage(onpackage []byte) (string){

	var oP onboardinScript
	var opS packages 

	if strings.Contains(string([]byte(onpackage)), "error"){	
		return "error here"
	}else{
		err := json.Unmarshal(onpackage, &oP)
		if err != nil{
			log.Fatal(err)
		}
		pack := json.Unmarshal(oP.Properties, &opS)
		if pack != nil{
			log.Fatal(pack)
		}
	}	
	return string(opS.Windows)

}
