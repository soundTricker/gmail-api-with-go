package gmailApi

import (
	"appengine"
	"appengine/datastore"
	"appengine/urlfetch"
	"appengine/user"
	"bytes"
	"code.google.com/p/goauth2/oauth"
	"encoding/json"
	"github.com/mjibson/goon"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/mail"
	"strings"
	"time"

	gmail "code.google.com/p/google-api-go-client/gmail/v1"
	"fmt"
	"github.com/alexcesaro/mail/gomail"
	"mime/multipart"
	"net/textproto"
	"runtime"
	"sort"
)

const (
	CLIENT_ID     = ""
	CLIENT_SECRET = ""
)

var config = &oauth.Config{
	ClientId:     CLIENT_ID,
	ClientSecret: CLIENT_SECRET,
	Scope:        "https://mail.google.com/",
	AuthURL:      "https://accounts.google.com/o/oauth2/auth",
	TokenURL:     "https://accounts.google.com/o/oauth2/token",
	AccessType:   "offline",
}

type Credential struct {
	Email        string `datastore:"-" goon:"id"`
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
}

type Raw struct {
	Raw []byte `json:"raw"`
}

func init() {
	var url string
	if !appengine.IsDevAppServer() {
		url = "https://compute-engine-sandbox.appspot.com"
	} else {
		url = "http://localhost:8080"
	}
	config.RedirectURL = url + "/oauth2callback"

	http.HandleFunc("/", showIndex)
	http.HandleFunc("/oauth2callback", oauth2callback)
	http.HandleFunc("/sendMail", sendMail)
	http.HandleFunc("/sendBatch", sendMailBatch)
	http.HandleFunc("/analyze", showAnalyze)
	http.HandleFunc("/analyzing", analyze)
}

func analyze(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	u := user.Current(c)

	if u == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	g := goon.NewGoon(r)
	tokenInfo := &Credential{Email: u.Email}
	if err := g.Get(tokenInfo); err == datastore.ErrNoSuchEntity {
		http.Redirect(w, r, config.AuthCodeURL(""), http.StatusTemporaryRedirect)
		return
	}

	if len(r.PostFormValue("searchText")) == 0 {
		http.Error(w, "Given search text", http.StatusBadRequest)
		return

	}

	transport := &oauth.Transport{
		Config:    config,
		Transport: &urlfetch.Transport{Context: c},
	}

	transport.Token = &oauth.Token{
		AccessToken:  tokenInfo.AccessToken,
		RefreshToken: tokenInfo.RefreshToken,
		Expiry:       tokenInfo.Expiry,
	}

	if transport.Expired() {
		if err := transport.Refresh(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	service, err := gmail.New(transport.Client())

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	messageRes, err := service.Users.Messages.List("me").Q(r.PostFormValue("searchText")).Do()

	if err != nil {
		panic(err.Error())
	}
	receiver, fin := worker(service, messageRes.Messages)
	result := make(map[string]int)

	for {
		select {
		case receive := <-receiver:
			for k, v := range receive {
				if _, ok := result[k]; ok {
					result[k] += v
				} else {
					result[k] = v
				}
			}
		case <-fin:

			data := make(Words, 0, len(result))

			for k, v := range result {
				data = append(data, &Word{k, v})
			}

			sort.Sort(data)
			w.WriteHeader(200)
			json.NewEncoder(w).Encode(data)
			return
		}
	}
}

func showAnalyze(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	u := user.Current(c)

	if u == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	g := goon.FromContext(c)
	tokenInfo := &Credential{Email: u.Email}
	if err := g.Get(tokenInfo); err == datastore.ErrNoSuchEntity {
		http.Redirect(w, r, config.AuthCodeURL(""), http.StatusTemporaryRedirect)
		return
	}

	transport := &oauth.Transport{
		Config:    config,
		Transport: &urlfetch.Transport{Context: c},
	}

	transport.Token = &oauth.Token{
		AccessToken:  tokenInfo.AccessToken,
		RefreshToken: tokenInfo.RefreshToken,
		Expiry:       tokenInfo.Expiry,
	}

	if transport.Expired() {
		if err := transport.Refresh(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	form := template.Must(template.ParseFiles("template/analyze.tmpl.html"))

	if err := form.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func sendMailBatch(w http.ResponseWriter, r *http.Request) {

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

	g := goon.FromContext(c)
	tokenInfo := &Credential{Email: u.Email}

	if err := g.Get(tokenInfo); err == datastore.ErrNoSuchEntity {
		http.Redirect(w, r, config.AuthCodeURL(""), http.StatusTemporaryRedirect)
		return
	}

	transport := &oauth.Transport{
		Config:    config,
		Transport: &urlfetch.Transport{Context: c},
	}

	transport.Token = &oauth.Token{
		AccessToken:  tokenInfo.AccessToken,
		RefreshToken: tokenInfo.RefreshToken,
		Expiry:       tokenInfo.Expiry,
	}

	if transport.Expired() {
		if err := transport.Refresh(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	client := &http.Client{
		Transport: transport,
	}

	b := &bytes.Buffer{}

	m := multipart.NewWriter(b)

	for i := 0; i < 1000; i++ {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Type", "application/http")

		bw, err := m.CreatePart(h)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Fprintln(bw, "POST /gmail/v1/users/me/messages/send")
		fmt.Fprintln(bw, "Content-Type: application/json")
		fmt.Fprintln(bw, "")

		msg := gomail.NewCustomMessage("UTF-8", gomail.Base64)

		msg.SetAddressHeader("From", u.Email, "")
		msg.SetAddressHeader("To", r.FormValue("to"), "")
		msg.SetHeader("Delivered-To", r.FormValue("to"))
		msg.SetHeader("Subject", r.FormValue("subject"))
		msg.SetBody("text/plain", r.FormValue("body"))

		message, err := msg.Export()

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fh := flattenHeader(message, "")
		body, err := ioutil.ReadAll(message.Body)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		err = json.NewEncoder(bw).Encode(&Raw{Raw: append(fh, body...)})

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	c.Debugf(string(b.Bytes()))

	m.Close()

	resp, err := client.Post("https://www.googleapis.com/batch", "multipart/mixed; boundary="+m.Boundary(), bytes.NewReader(b.Bytes()))

	c.Debugf("sended")

	if resp != nil {
		bb, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return

		}

		fmt.Fprintf(w, string(bb))
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

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

	g := goon.FromContext(c)
	tokenInfo := &Credential{Email: u.Email}

	if err := g.Get(tokenInfo); err == datastore.ErrNoSuchEntity {
		http.Redirect(w, r, config.AuthCodeURL(""), http.StatusTemporaryRedirect)
		return
	}

	transport := &oauth.Transport{
		Config:    config,
		Transport: &urlfetch.Transport{Context: c},
	}

	transport.Token = &oauth.Token{
		AccessToken:  tokenInfo.AccessToken,
		RefreshToken: tokenInfo.RefreshToken,
		Expiry:       tokenInfo.Expiry,
	}

	if transport.Expired() {
		if err := transport.Refresh(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	client := &http.Client{
		Transport: transport,
	}

	msg := gomail.NewCustomMessage("UTF-8", gomail.Base64)

	msg.SetAddressHeader("From", u.Email, "")
	msg.SetAddressHeader("To", r.FormValue("to"), "")
	msg.SetHeader("Delivered-To", r.FormValue("to"))
	msg.SetHeader("Subject", r.FormValue("subject"))
	msg.SetBody("text/plain", r.FormValue("body"))

	message, err := msg.Export()

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h := flattenHeader(message, "")
	body, err := ioutil.ReadAll(message.Body)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	c.Debugf(string(append(h, body...)))

	b, err := json.Marshal(&Raw{Raw: append(h, body...)})

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

	fmt.Fprintf(w, string(b))
}

func flattenHeader(msg *mail.Message, bcc string) []byte {
	var buffer bytes.Buffer
	for field, value := range msg.Header {
		if field != "Bcc" {
			buffer.WriteString(field + ": " + strings.Join(value, ", ") + "\r\n")
		} else if bcc != "" {
			for _, to := range value {
				if strings.Contains(to, bcc) {
					buffer.WriteString(field + ": " + to + "\r\n")
				}
			}
		}
	}
	buffer.WriteString("\r\n")

	return buffer.Bytes()
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

	config := &oauth.Config{
		ClientId:     CLIENT_ID,
		ClientSecret: CLIENT_SECRET,
		RedirectURL:  url + "/oauth2callback",
		Scope:        "https://mail.google.com/",
		AuthURL:      "https://accounts.google.com/o/oauth2/auth",
		TokenURL:     "https://accounts.google.com/o/oauth2/token",
		AccessType:   "offline",
	}

	g := goon.FromContext(c)
	tokenInfo := &Credential{Email: u.Email}

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

	transport := &oauth.Transport{
		Config:    config,
		Transport: &urlfetch.Transport{Context: c},
	}

	token, err := transport.Exchange(code)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	g := goon.FromContext(c)

	if resp, err := g.Put(&Credential{Email: u.Email, AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, Expiry: token.Expiry}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else {
		c.Debugf(resp.String())
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)

}
