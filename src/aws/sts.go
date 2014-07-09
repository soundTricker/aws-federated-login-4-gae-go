package main

import (
	"github.com/bridger/aws4"
	"time"
	"net/url"
	"encoding/xml"
	"strconv"
	"encoding/json"
	"fmt"
)

const (
	signinUrl = "https://signin.aws.amazon.com/federation"
)

type GetFederationTokenResponse struct {
	RequestId   string      `xml:"ResponseMetadata>RequestId"`
	Credentials Credentials `xml:"GetFederationTokenResult>Credentials"`
}
type Credentials struct {
	SessionToken    string
	SecretAccessKey string
	Expiration      time.Time
	AccessKeyId     string
}

type SigninToken struct {
	SigninToken string
}

type Session struct {
	SessionId    string `json:"sessionId"`
	SessionToken string `json:"sessionToken"`
	SessionKey   string `json:"sessionKey"`
}


const (
	DEFAULT_DURATION_SECONDS = 43200
	DEFAULT_DESTINATION_URL = "https://console.aws.amazon.com/console/home"
)

type Sts struct {
	Client *aws4.Client
}

func (t *Sts) GetFederationToken(username , policy string, durationSeconds int) (result *GetFederationTokenResponse, err error) {

	vals := make(url.Values)

	vals.Set("Version", "2011-06-15")
	vals.Set("Action", "GetFederationToken")
	vals.Set("Name", username)
	vals.Set("Policy", policy)
	vals.Set("DurationSeconds", strconv.Itoa(durationSeconds))

	res, err := t.Client.PostForm("https://sts.amazonaws.com/", vals)

	if err != nil {
		return
	}

	result = new(GetFederationTokenResponse)
	if err = xml.NewDecoder(res.Body).Decode(&result); err != nil {
		return
	}

	return
}

func (t *Sts) GetSigninToken(session *Session) (result *SigninToken, err error){
	sessionJson, err := json.Marshal(session)

	if err != nil {
		return
	}

	vals := make(url.Values)

	vals.Set("Action", "getSigninToken")
	vals.Set("SessionType", "json")
	vals.Set("Session", string(sessionJson))

	res, err := t.Client.Get(signinUrl + "?" + vals.Encode())

	if err != nil {
		return
	}

	result = new(SigninToken)
	if err = json.NewDecoder(res.Body).Decode(&result); err != nil {
		return
	}
	return
}

func (t *Sts) GenerateFederatedLoginUrl(signinToken *SigninToken, issuer, destination string) string {
	vals := make(url.Values)

	vals.Set("Action", "login")
	vals.Set("SigninToken", signinToken.SigninToken)
	vals.Set("Issuer", issuer)
	vals.Set("Destination", destination)

	return fmt.Sprintf("%s?%s", signinUrl, vals.Encode())
}
