package main

import (
	"appengine"
	"appengine/urlfetch"
	"appengine/user"
	"encoding/json"
	"github.com/bridger/aws4"
	"io/ioutil"
	"net/http"
	"strings"
)

func init() {
	http.HandleFunc("/", handler)
}

func handler(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)

	u := user.Current(c)

	if u == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if !strings.HasSuffix(u.Email, "@bfts.co.jp") {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	c.Debugf(u.Email)

	var keys *aws4.Keys
	if b, err := ioutil.ReadFile("resources/AWSCredentials.json"); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	} else if err = json.Unmarshal(b, &keys); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	username := strings.TrimSuffix(u.Email, "@bfts.co.jp")

	sts := &Sts{
		Client: &aws4.Client{
			Keys: keys,
			Client: urlfetch.Client(c),
		},
	}

	federationTokenResponse, err := sts.GetFederationToken(username, `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "ec2:*",
      "Effect": "Allow",
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Condition": {
        "StringLike": {
          "ec2:InstanceType": ["t1.*","m3.*", "c3.*","r3.*","g2.*","i2.*","hs1.*","m1.*"]
        }
      },
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Condition": {
        "NumericGreaterThan": {
          "ec2:VolumeSize": "8"
        }
      },
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "elasticloadbalancing:*",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "cloudwatch:*",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "autoscaling:*",
      "Resource": "*"
    }
  ]
}`, DEFAULT_DURATION_SECONDS)

	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	session := &Session{
		SessionId:    federationTokenResponse.Credentials.AccessKeyId,
		SessionToken: federationTokenResponse.Credentials.SessionToken,
		SessionKey:   federationTokenResponse.Credentials.SecretAccessKey,
	}

	signinToken, err := sts.GetSigninToken(session)

	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	var protocol string
	if appengine.IsDevAppServer() {
		protocol = "http://"
	} else {
		protocol = "https://"
	}

	http.Redirect(w, r, sts.GenerateFederatedLoginUrl(
		signinToken,
		protocol+appengine.DefaultVersionHostname(c),
		DEFAULT_DESTINATION_URL,
	), http.StatusFound)

}
