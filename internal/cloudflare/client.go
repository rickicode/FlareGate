package cloudflare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 20 * time.Second}

// Request performs a request to the Cloudflare V4 API.
//
// It always returns the parsed JSON body when possible, plus the HTTP status
// code. Non-2xx responses are returned as errors with a useful message, but the
// parsed payload is still returned so callers can inspect Cloudflare's details.
func Request(method, endpoint, token string, body interface{}) (map[string]interface{}, int, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		bodyReader = bytes.NewBuffer(jsonBody)
	}

	requestURL := "https://api.cloudflare.com/client/v4" + endpoint
	req, err := http.NewRequest(method, requestURL, bodyReader)
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "FlareGate/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	result := map[string]interface{}{}
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &result); err != nil {
			return nil, resp.StatusCode, err
		}
	}

	if resp.StatusCode >= http.StatusBadRequest {
		msg := extractCloudflareMessage(result)
		if msg == "" {
			msg = strings.TrimSpace(string(respBody))
		}
		if msg == "" {
			msg = resp.Status
		}
		return result, resp.StatusCode, fmt.Errorf("%s", msg)
	}

	if success, ok := result["success"].(bool); ok && !success {
		msg := extractCloudflareMessage(result)
		if msg == "" {
			msg = "Cloudflare API returned success=false"
		}
		return result, resp.StatusCode, fmt.Errorf("%s", msg)
	}

	return result, resp.StatusCode, nil
}

func extractCloudflareMessage(result map[string]interface{}) string {
	if len(result) == 0 {
		return ""
	}

	if errorsList, ok := result["errors"].([]interface{}); ok && len(errorsList) > 0 {
		if first, ok := errorsList[0].(map[string]interface{}); ok {
			if msg, ok := first["message"].(string); ok && msg != "" {
				return msg
			}
		}
	}

	if messages, ok := result["messages"].([]interface{}); ok && len(messages) > 0 {
		if first, ok := messages[0].(map[string]interface{}); ok {
			if msg, ok := first["message"].(string); ok && msg != "" {
				return msg
			}
		}
	}

	if msg, ok := result["message"].(string); ok && msg != "" {
		return msg
	}

	if res, ok := result["result"].(map[string]interface{}); ok {
		if msg, ok := res["message"].(string); ok && msg != "" {
			return msg
		}
	}

	return ""
}

func GetTunnelToken(accountID, tunnelID, apiToken string) (string, error) {
	endpoint := fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/token", accountID, tunnelID)
	res, code, err := Request("GET", endpoint, apiToken, nil)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("API/token returned status %d", code)
	}

	if result, ok := res["result"].(string); ok {
		return result, nil
	}
	if result, ok := res["result"].(map[string]interface{}); ok {
		if token, ok := result["token"].(string); ok && token != "" {
			return token, nil
		}
	}
	return "", fmt.Errorf("failed to parse token from response")
}

func tunnelConfigEndpoint(accountID, tunnelID string) string {
	return fmt.Sprintf("/accounts/%s/cfd_tunnel/%s/configurations", accountID, tunnelID)
}

func GetTunnelConfig(accountID, tunnelID, apiToken string) (map[string]interface{}, error) {
	res, code, err := Request("GET", tunnelConfigEndpoint(accountID, tunnelID), apiToken, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("tunnel config returned status %d", code)
	}

	resultObj, _ := res["result"].(map[string]interface{})
	if resultObj == nil {
		return map[string]interface{}{}, nil
	}
	configObj, _ := resultObj["config"].(map[string]interface{})
	if configObj == nil {
		return map[string]interface{}{}, nil
	}
	return configObj, nil
}

func GetTunnelIngress(accountID, tunnelID, apiToken string) ([]interface{}, error) {
	configObj, err := GetTunnelConfig(accountID, tunnelID, apiToken)
	if err != nil {
		return nil, err
	}
	if ingress, ok := configObj["ingress"].([]interface{}); ok {
		return ingress, nil
	}
	return []interface{}{}, nil
}

func UpdateTunnelIngress(accountID, tunnelID, apiToken string, ingress []interface{}) error {
	payload := map[string]interface{}{
		"config": map[string]interface{}{
			"ingress": ingress,
		},
	}
	_, _, err := Request("PUT", tunnelConfigEndpoint(accountID, tunnelID), apiToken, payload)
	return err
}

func VisibleIngressRules(ingress []interface{}) []interface{} {
	visible := make([]interface{}, 0, len(ingress))
	for _, item := range ingress {
		rule, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		hostname, _ := rule["hostname"].(string)
		if strings.TrimSpace(hostname) == "" {
			continue
		}
		visible = append(visible, rule)
	}
	return visible
}

func FindZoneByName(apiToken, name string) (map[string]interface{}, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, nil
	}
	res, _, err := Request("GET", "/zones?name="+url.QueryEscape(name), apiToken, nil)
	if err != nil {
		return nil, err
	}
	results, _ := res["result"].([]interface{})
	for _, item := range results {
		if zone, ok := item.(map[string]interface{}); ok {
			return zone, nil
		}
	}
	return nil, nil
}

func ResolveZoneByHostname(apiToken, hostname string) (string, string, error) {
	hostname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
	for _, candidate := range zoneCandidates(hostname) {
		zone, err := FindZoneByName(apiToken, candidate)
		if err != nil {
			return "", "", err
		}
		if zone == nil {
			continue
		}
		zoneID, _ := zone["id"].(string)
		zoneName, _ := zone["name"].(string)
		if zoneID != "" {
			return zoneID, zoneName, nil
		}
	}
	return "", "", fmt.Errorf("could not find cloudflare zone for %s", hostname)
}

func zoneCandidates(hostname string) []string {
	parts := strings.Split(hostname, ".")
	seen := map[string]bool{}
	candidates := make([]string, 0, 3)
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		candidates = append(candidates, value)
	}

	if len(parts) >= 2 {
		add(strings.Join(parts[len(parts)-2:], "."))
	} else {
		add(hostname)
	}
	add(hostname)
	if len(parts) > 2 {
		add(strings.Join(parts[len(parts)-3:], "."))
	}
	return candidates
}

func ListDNSRecordsByName(apiToken, zoneID, hostname string) ([]map[string]interface{}, error) {
	endpoint := fmt.Sprintf("/zones/%s/dns_records?name=%s", zoneID, url.QueryEscape(hostname))
	res, _, err := Request("GET", endpoint, apiToken, nil)
	if err != nil {
		return nil, err
	}
	items, _ := res["result"].([]interface{})
	records := make([]map[string]interface{}, 0, len(items))
	for _, item := range items {
		record, ok := item.(map[string]interface{})
		if ok {
			records = append(records, record)
		}
	}
	return records, nil
}

func DeleteDNSRecord(apiToken, zoneID, recordID string) error {
	_, _, err := Request("DELETE", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID), apiToken, nil)
	return err
}

func EnsureTunnelDNSRecord(apiToken, zoneID, hostname, tunnelID, comment string) (map[string]interface{}, error) {
	content := fmt.Sprintf("%s.cfargotunnel.com", tunnelID)
	payload := map[string]interface{}{
		"type":    "CNAME",
		"name":    hostname,
		"content": content,
		"proxied": true,
		"comment": comment,
	}

	records, err := ListDNSRecordsByName(apiToken, zoneID, hostname)
	if err != nil {
		return nil, err
	}

	var desiredCNAME map[string]interface{}
	for _, record := range records {
		recordType := strings.ToUpper(fmt.Sprintf("%v", record["type"]))
		if recordType == "CNAME" && desiredCNAME == nil {
			desiredCNAME = record
			continue
		}
		if recordType == "A" || recordType == "CNAME" {
			recordID, _ := record["id"].(string)
			if strings.TrimSpace(recordID) != "" {
				if err := DeleteDNSRecord(apiToken, zoneID, recordID); err != nil {
					return nil, err
				}
			}
		}
	}

	if desiredCNAME != nil {
		recordID, _ := desiredCNAME["id"].(string)
		existingContent, _ := desiredCNAME["content"].(string)
		proxied, proxiedOK := desiredCNAME["proxied"].(bool)
		if existingContent == content && (!proxiedOK || proxied) {
			return desiredCNAME, nil
		}
		res, _, err := Request("PUT", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID), apiToken, payload)
		if err != nil {
			return nil, err
		}
		return parseDNSRecordResult(res)
	}

	res, _, err := Request("POST", fmt.Sprintf("/zones/%s/dns_records", zoneID), apiToken, payload)
	if err != nil {
		return nil, err
	}
	return parseDNSRecordResult(res)
}

func DeleteTunnelDNSRecordsByHostname(apiToken, zoneID, hostname string) (bool, error) {
	records, err := ListDNSRecordsByName(apiToken, zoneID, hostname)
	if err != nil {
		return false, err
	}
	deleted := false
	for _, record := range records {
		recordType := strings.ToUpper(fmt.Sprintf("%v", record["type"]))
		if recordType != "A" && recordType != "CNAME" {
			continue
		}
		recordID, _ := record["id"].(string)
		if strings.TrimSpace(recordID) == "" {
			continue
		}
		if err := DeleteDNSRecord(apiToken, zoneID, recordID); err != nil {
			return deleted, err
		}
		deleted = true
	}
	return deleted, nil
}

func parseDNSRecordResult(res map[string]interface{}) (map[string]interface{}, error) {
	result, ok := res["result"].(map[string]interface{})
	if !ok || result == nil {
		return nil, fmt.Errorf("failed to parse DNS record result")
	}
	return result, nil
}
