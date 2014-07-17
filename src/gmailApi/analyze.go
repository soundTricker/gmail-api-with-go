package gmailApi

import (
	gmail "code.google.com/p/google-api-go-client/gmail/v1"
	"encoding/base64"
	"github.com/ikawaha/kagome/tokenizer"
	"log"
	"sync"
)

type Word struct {
	Name  string
	Count int
}

type Words []*Word

func (w Words) Len() int { return len(w) }

func (w Words) Swap(i, j int) { w[i], w[j] = w[j], w[i] }

func (w Words) Less(i, j int) bool { return w[i].Count > w[j].Count }

func worker(service *gmail.Service, messages []*gmail.Message) (<-chan map[string]int, <-chan bool) {

	var wg sync.WaitGroup
	receiver := make(chan map[string]int)
	fin := make(chan bool)

	go func() {
		for _, message := range messages {

			wg.Add(1)

			go func(message *gmail.Message) {
				t := tokenizer.NewTokenizer()
				result := make(map[string]int)
				message, err := service.Users.Messages.Get("me", message.Id).Do()

				if err != nil {
					panic(err.Error())
				}

				log.Println(message.Payload.MimeType)
				if message.Payload.Body.Size != 0 {

					body, err := base64.URLEncoding.DecodeString(message.Payload.Body.Data)

					if err != nil {
						panic(err.Error())
					}

					morphs, err := t.Tokenize(string(body))

					for _, morph := range morphs {
						if morph.Id == tokenizer.BOSEOS {
							break
						}

						content, err := morph.Content()

						if err != nil {
							continue
						}

						if content.Pos != "名詞" || content.Pos1 != "固有名詞" {
							continue
						}

						if count, ok := result[morph.Surface]; ok {
							result[morph.Surface] = count + 1
						} else {
							result[morph.Surface] = 1
						}
					}

				} else {
					//					log.Println(message.Payload.Parts[0].Body.Data)
				}

				receiver <- result
				wg.Done()

			}(message)
		}
		wg.Wait()

		fin <- false
	}()

	return receiver, fin
}
