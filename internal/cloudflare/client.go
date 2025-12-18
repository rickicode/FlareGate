package cloudflare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Request performs a request to the Cloudflare V4 API
func Request(method, endpoint, token string, body interface{}) (map[string]interface{}, int, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		bodyReader = bytes.NewBuffer(jsonBody)
	}

	url := "https://api.cloudflare.com/client/v4" + endpoint
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, resp.StatusCode, err
	}

	return result, resp.StatusCode, nil
}

func GetTunnelToken(accountID, tunnelID, apiToken string) (string, error) {
	endpoint := fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/token", accountID, tunnelID)
	res, code, err := Request("GET", endpoint, apiToken, nil)
	if err != nil {
		return "", err
	}
	if code != 200 {
		return "", fmt.Errorf("API/token returned status %d", code)
	}
	
	if result, ok := res["result"].(string); ok {
		return result, nil
	}
	return "", fmt.Errorf("failed to parse token from response")
}
