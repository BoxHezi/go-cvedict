package model

import (
	"bytes"
	"encoding/json"
	"net/http"

	"cvedict/utils"
)

/*
Notifier, currently support for discord only
*/
type Notifier struct {
	url     string
	content string
}

func CreateNotifier(flags RootFlag) *Notifier {
	var n *Notifier = new(Notifier)
	if (*flags.GetNotifierUrlP() == "") || (flags.GetNotifierUrlP() == nil) {
		return nil
	}
	n.url = *flags.GetNotifierUrlP()
	return n
}

func (n *Notifier) SetUrl(url string) {
	n.url = url
}

func (n *Notifier) GetUrl() string {
	return n.url
}

func (n *Notifier) SetContent(content string) {
	n.content = content
}

func (n *Notifier) GetContent() string {
	return n.content
}

func (n *Notifier) Send() {
	payload := map[string]string{
		"content": n.content,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		utils.LogError(err)
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", n.url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		utils.LogError(err)
	}
	req.Header.Set("Content-Type", "application/json")

	_, err = client.Do(req)
	if err != nil {
		utils.LogError(err)
	}
}
