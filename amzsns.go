// Copyright 2011-2013 Claypost Inc
// Use of this source code is governed by an MIT-style license
// that can be found in the LICENSE file.
// The code is largely based on amzses from Numrotron Inc written by Patrick Crosby

package amzsns

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "github.com/crowdmob/goamz/aws"
    "github.com/stathat/jconfig"
    "io/ioutil"
    "log"
    "net/http"
    "net/url"
    "sort"
    "strings"
    "time"
)

// Using text directly on "alert" since no alert dictionary values are going to be used
type APNSMessageType struct {
	Alert                   string  `json:"alert"`
	Badge                   string  `json:"badge"`
	Sound                   string `json:"sound"`
}

const (
    endpoint = "http://sns.us-west-2.amazonaws.com"
)

var accessKey, secretKey string
var b64 = base64.StdEncoding

func init() {
    config := jconfig.LoadConfig("/etc/aws.conf")
    accessKey = config.GetString("aws_access_key")
    secretKey = config.GetString("aws_secret_key")
}

func CreateEndPoint(host, platformApplicationARN, customerUserData, token string) (string, error) {
    method := "POST"
    path := ""
    now := time.Now().UTC()
    // date format: "Tue, 25 May 2010 21:20:27 +0000"
    //date := now.Format("Mon, 02 Jan 2006 15:04:05 -0700")
    
    // 8601
    date := now.Format(time.RFC3339)
    
    params := make(map[string]string)
    /*
    params["Action"] = "CreatePlatformEndpoint"
    params["PlatformApplicationArn"] = platformApplicationARN
    params["CustomUserData"] = customerUserData
    params["Token"] = token
    params["Version"] = "2010-03-31"
    params["Timestamp"] = date
    params["AWSAccessKeyId"] = accessKey
    params["SignatureVersion"] = "2"
    params["SignatureMethod"] = "HmacSHA256"


    var sarray []string
    for k, v := range params {
	sarray = append(sarray, aws.Encode(k)+"="+aws.Encode(v))
    }
    sort.StringSlice(sarray).Sort()
    joined := strings.Join(sarray, "&")
    payload := method + "\n" + host + "\n" + path + "\n" + joined
        */
    payload := method + "\n" + host + "\n" + path + "/\n"
    hash := hmac.New(sha256.New, []byte(secretKey))
    hash.Write([]byte(payload))
    signature := make([]byte, b64.EncodedLen(hash.Size()))
    b64.Encode(signature, hash.Sum(nil))

    params["Signature"] = string(signature)
    log.Printf("amzsns.CreateEndPoint: payload: %s", payload)
    
    data := make(url.Values)
    data.Add("Action", "CreatePlatformEndpoint")
    data.Add("SignatureMethod", "HmacSHA256")
    data.Add("PlatformApplicationArn", platformApplicationARN)
    data.Add("CustomUserData", customerUserData)
    data.Add("Token", token)
    data.Add("AWSAccessKeyId", accessKey)
    data.Add("SignatureVersion", "2")
    data.Add("Signature", string(signature))
    data.Add("Version", "2010-03-31")
    data.Add("Timestamp", date)

    return snsPost(data)
}

func PublishAPNS(targetARN, alertMessage, badge, sound string) (string, error) {
    message := new(APNSMessageType)
    message.Alert = alertMessage
    if (0 != len(badge)) {
        message.Badge = badge
    }
    if (0 != len(sound)) {
        message.Sound = sound
    }
    jsonMessage, err := json.Marshal(message)
    if err != nil {
        log.Printf("json error: %s", err)
        return "", err
    }
    return PublishMobile(targetARN, string(jsonMessage))
}

func PublishMobile(targetARN, message string) (string, error) {
    now := time.Now().UTC()
    // date format: "Tue, 25 May 2010 21:20:27 +0000"
    date := now.Format("Mon, 02 Jan 2006 15:04:05 -0700")
    
    h := hmac.New(sha256.New, []uint8(secretKey))
    h.Write([]uint8(date))
    signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
    //auth := fmt.Sprintf("AWS3-HTTPS AWSAccessKeyId=%s, Algorithm=HmacSHA256, Signature=%s", accessKey, signature)
    
    data := make(url.Values)
    data.Add("Action", "Publish")
    data.Add("TargetArn", targetARN)
    data.Add("Message", message)
    data.Add("MessageStructure", "json")
    data.Add("SignatureMethod", "HmacSHA256")
    data.Add("AWSAccessKeyId", accessKey)
    data.Add("SignatureVersion", "2")
    data.Add("Signature", signature)
    data.Add("Version", "2010-03-31")
    data.Add("Timestamp", date)

    return snsPost(data)
}
/*
func sign(auth aws.Auth, method, path string, params map[string]string, host string) {
	params["AWSAccessKeyId"] = auth.AccessKey
	params["SignatureVersion"] = "2"
	params["SignatureMethod"] = "HmacSHA256"

	var sarray []string
	for k, v := range params {
		sarray = append(sarray, aws.Encode(k)+"="+aws.Encode(v))
	}
	sort.StringSlice(sarray).Sort()
	joined := strings.Join(sarray, "&")
	payload := method + "\n" + host + "\n" + path + "\n" + joined
	hash := hmac.New(sha256.New, []byte(auth.SecretKey))
	hash.Write([]byte(payload))
	signature := make([]byte, b64.EncodedLen(hash.Size()))
	b64.Encode(signature, hash.Sum(nil))

	params["Signature"] = string(signature)
}
*/

func snsPost(data url.Values) (string, error) {
    body := strings.NewReader(data.Encode())
    req, err := http.NewRequest("POST", endpoint, body)
    if err != nil {
        return "", err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    r, err := http.DefaultClient.Do(req)
    if err != nil {
        log.Printf("http error: %s", err)
        return "", err
    }

    resultbody, _ := ioutil.ReadAll(r.Body)
    r.Body.Close()

    if r.StatusCode != 200 {
        log.Printf("error, status = %d", r.StatusCode)

        log.Printf("error response: %s", resultbody)
        return "", errors.New(fmt.Sprintf("error code %d. response: %s", r.StatusCode, resultbody))
    }

    return string(resultbody), nil
}
