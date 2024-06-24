package notifier

import (
	"bytes"
	"encoding/json"
	"net/http"

	utils "cvedict/utils"
)

/*
Notifier, currently support for discord only
*/
type Notifier struct {
	url string
}

func (n *Notifier) SetUrl(url string) {
	n.url = url
}

func (n *Notifier) GetUrl() string {
	return n.url
}

func (n *Notifier) Send(data string) {
	content := map[string]string{
		"content": data,
	}
	jsonPayload, _ := json.Marshal(content)

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
