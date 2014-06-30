package gmailApi

import (
	"fmt"
	"encoding/base64"
	"net/mail"
	"strings"
	"time"
	"bytes"
)


type Message struct {
	From *mail.Address
	To []*mail.Address
	Cc []*mail.Address
	Bcc []*mail.Address
	Subject string
	Body []byte
}

func encode(x string) string {
	return base64.URLEncoding.EncodeToString([]byte(x))
}

func encode2(x string) string {
	return fmt.Sprintf("=?UTF-8?B?%v?=", encode(x))
}

// 76バイト毎にCRLFを挿入する
func add76crlf(msg string) string {
	var buffer bytes.Buffer
	for k, c := range strings.Split(msg, "") {
		buffer.WriteString(c)
		if k%76 == 75 {
			buffer.WriteString("\r\n")
		}
	}
	return buffer.String()
}

// UTF8文字列を指定文字数で分割
func utf8Split(utf8string string, length int) []string {
	resultString := []string{}
	var buffer bytes.Buffer
	for k, c := range strings.Split(utf8string, "") {
		buffer.WriteString(c)
		if k%length == length-1 {
			resultString = append(resultString, buffer.String())
			buffer.Reset()
		}
	}
	if buffer.Len() > 0 {
		resultString = append(resultString, buffer.String())
	}
	return resultString
}

// サブジェクトをMIMEエンコードする
func encodeSubject(subject string) string {
	var buffer bytes.Buffer
	buffer.WriteString("Subject:")
	for _, line := range utf8Split(subject, 13) {
		buffer.WriteString(" =?UTF-8?B?")
		buffer.WriteString(base64.StdEncoding.EncodeToString([]byte(line)))
		buffer.WriteString("?=\r\n")
	}
	return buffer.String()
}


func (m Message) Sender() string {
	return m.From.Address
}

func (m Message) Recipients() (recipients []string) {
	for _, addr := range append(m.To, append(m.Cc, m.Bcc...)...) {
		recipients = append(recipients, addr.Address)
	}
	return
}


func (m Message) String() string{
	msg := "MIME-Version : 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n"
	msg += fmt.Sprintf("Date: %v\r\n", time.Now().Format(time.RFC822))
	msg += fmt.Sprintf("From: %v\r\n", m.From.Address)

	var tos, ccs, bccs []string
	for _, addr := range m.To {
		tos = append(tos, addr.Address)
	}
	for _, addr := range m.Cc {
		ccs = append(ccs, addr.Address)
	}
	for _, addr := range m.Bcc {
		bccs = append(bccs, addr.Address)
	}
	msg += fmt.Sprintf("To: %v\r\n", strings.Join(tos, ", "))

	if len(ccs) > 1 {
		msg += fmt.Sprintf("Cc: %v\r\n", strings.Join(ccs, ", "))
	}
	if len(bccs) > 1 {
		msg += fmt.Sprintf("Bcc: %v\r\n", strings.Join(bccs, ","))
	}

	msg += fmt.Sprintf("Delivered-To: %v\r\n", strings.Join(tos, ", "))

	msg += fmt.Sprintf("%v\r\n%v", encodeSubject(m.Subject), encode(string(m.Body)))


	return msg
}
