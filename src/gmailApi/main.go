package gmailApi

import (
	"net/http"
	"appengine"
	"appengine/user"
	"strings"
	"code.google.com/p/goauth2/oauth"
	"github.com/mjibson/goon"
	"appengine/datastore"
	"appengine/urlfetch"
	"time"
	"html/template"
	"net/mail"
	"encoding/json"
	"bytes"
	"io/ioutil"

)

const (
	CLIENT_ID = ""
	CLIENT_SECRET = ""
)

type Credential struct {
	Email string `datastore:"-" goon:"id"`
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
}

type Raw struct {
	Raw []byte `json:"raw"`
}




func init() {
	http.HandleFunc("/", showIndex)
	http.HandleFunc("/oauth2callback", oauth2callback)
	http.HandleFunc("/sendMail", sendMail)
}

func sendMail(w http.ResponseWriter, r *http.Request) {

	c := appengine.NewContext(r)

	u := user.Current(c)

	if u == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if len(r.FormValue("to")) == 0 || len(r.FormValue("subject")) == 0 || len(r.FormValue("body")) == 0 {
		http.Error(w, "Should not set empty values", http.StatusBadRequest)
		return
	}

	var url string

	if strings.Contains(r.Host, "appspot.com") {
		url = "https://compute-engine-sandbox.appspot.com"
	} else {
		url = "http://localhost:8080"
	}

	config := &oauth.Config {
		ClientId : CLIENT_ID,
		ClientSecret : CLIENT_SECRET,
		RedirectURL :  url + "/oauth2callback",
		Scope : "https://mail.google.com/",
		AuthURL : "https://accounts.google.com/o/oauth2/auth",
		TokenURL : "https://accounts.google.com/o/oauth2/token",
	}

	g := goon.FromContext(c)
	tokenInfo := &Credential{Email : u.Email}

	if err := g.Get(tokenInfo); err == datastore.ErrNoSuchEntity {
		http.Redirect(w, r, config.AuthCodeURL(""), http.StatusTemporaryRedirect)
		return
	}

	transport := &oauth.Transport{
		Config : config,
		Transport : &urlfetch.Transport {Context : c},
	}

	transport.Token = &oauth.Token {
		AccessToken : tokenInfo.AccessToken,
		RefreshToken : tokenInfo.RefreshToken,
		Expiry : tokenInfo.Expiry,
	}

	if transport.Expired() {
		if err := transport.Refresh(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}


	client := &http.Client {
		Transport : transport,
	}

	from, err := mail.ParseAddress(u.Email)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	to, err := mail.ParseAddressList(r.FormValue("to"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	message := &Message {
		To : to,
		From : from,
		Subject: r.FormValue("subject"),
		Body : []byte(r.FormValue("body")),
	}

	c.Debugf(message.String())

	b, err := json.Marshal(&Raw {Raw : []byte(message.String())})

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := client.Post("https://www.googleapis.com/gmail/v1/users/me/messages/send", "application/json", bytes.NewReader(b))

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return

	}

	b, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return

	}

	c.Debugf("%v",string(b))


	http.Redirect(w,r,"/", http.StatusTemporaryRedirect)

}

func showIndex(w http.ResponseWriter, r *http.Request) {

	c := appengine.NewContext(r)

	u := user.Current(c)

	if u == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var url string

	if strings.Contains(r.Host, "appspot.com") {
		url = "https://compute-engine-sandbox.appspot.com"
	} else {
		url = "http://localhost:8080"
	}

	config := &oauth.Config {
		ClientId : CLIENT_ID,
		ClientSecret : CLIENT_SECRET,
		RedirectURL :  url + "/oauth2callback",
		Scope : "https://mail.google.com/",
		AuthURL : "https://accounts.google.com/o/oauth2/auth",
		TokenURL : "https://accounts.google.com/o/oauth2/token",
		AccessType : "offline",
	}

	g := goon.FromContext(c)
	tokenInfo := &Credential{Email : u.Email}

	if err := g.Get(tokenInfo); err == datastore.ErrNoSuchEntity {
		http.Redirect(w, r, config.AuthCodeURL(""), http.StatusTemporaryRedirect)
		return
	}

	form := template.Must(template.ParseFiles("template/index.tmpl.html"))

	if err := form.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func oauth2callback(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)

	u := user.Current(c)

	if u == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	code := r.FormValue("code")
	if len(code) == 0 {
		http.Error(w, "Bad Request does not have code parameter", http.StatusBadRequest)
		return
	}


	var url string

	if strings.Contains(r.Host, "appspot.com") {
		url = "https://compute-engine-sandbox.appspot.com"
	} else {
		url = "http://localhost:8080"
	}

	config := &oauth.Config {
		ClientId : CLIENT_ID,
		ClientSecret : CLIENT_SECRET,
		RedirectURL :  url + "/oauth2callback",
		Scope : "https://mail.google.com/",
		AuthURL : "https://accounts.google.com/o/oauth2/auth",
		TokenURL : "https://accounts.google.com/o/oauth2/token",
	}

	transport := &oauth.Transport{
		Config : config,
		Transport : &urlfetch.Transport {Context : c},
	}

	token, err := transport.Exchange(code)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	g := goon.FromContext(c)

	if resp, err := g.Put(&Credential{Email : u.Email,AccessToken : token.AccessToken, RefreshToken : token.RefreshToken, Expiry: token.Expiry}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else {
		c.Debugf(resp.String())
	}



	http.Redirect(w,r,"/", http.StatusTemporaryRedirect)

}



