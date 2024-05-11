package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func (c *vercelDNSProviderSolver) makeVercelRequest(method, baseURL string, body []byte, apiToken string, queryParams map[string]string) ([]byte, error) {
	// Parse the base URL
	u, err := url.Parse(baseURL)
	if err != nil {
		log.Printf("Error parsing base URL: %v", err)
		return nil, err
	}

	// Prepare query parameters
	q := u.Query()
	for key, value := range queryParams {
		if value != "" {
			q.Set(key, value)
		}
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(method, u.String(), bytes.NewReader(body))
	if err != nil {
		log.Printf("Error creating HTTP request: %v", err)
		return nil, err
	}

	// Encode the API token before adding it to the header
	token := strings.TrimSpace(apiToken)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending HTTP request: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		return nil, err
	}

	if resp.StatusCode >= 400 {
		log.Printf("Error from Vercel API: %s", respBody)
		return nil, fmt.Errorf("error from Vercel API: %s", respBody)
	}

	return respBody, nil
}

// getVercelDomains retrieves all domains from Vercel for the account associated with the given API token.
func getVercelDomains(c *vercelDNSProviderSolver, apiToken string, queryParams map[string]string) ([]string, error) {
	var domains []string
	url := "https://api.vercel.com/v5/domains"

	for {

		responseBody, err := c.makeVercelRequest("GET", url, nil, apiToken, queryParams)
		if err != nil {
			return nil, err
		}

		var data struct {
			Domains []struct {
				Name string `json:"name"`
			} `json:"domains"`
			Pagination struct {
				Next string `json:"next"`
			} `json:"pagination"`
		}

		if err := json.Unmarshal(responseBody, &data); err != nil {
			return nil, fmt.Errorf("error decoding response JSON: %v", err)
		}

		for _, domain := range data.Domains {
			domains = append(domains, domain.Name)
		}

		if data.Pagination.Next == "" {
			break
		}
		url = data.Pagination.Next
	}

	return domains, nil
}

// matchDomain finds the most specific domain match for a given FQDN from a list of domains.
func matchDomain(fqdn string, domains []string) (string, error) {
	fqdn = strings.Trim(fqdn, ".") // clean up the FQDN
	fqdnParts := strings.Split(fqdn, ".")

	for len(fqdnParts) > 1 {
		candidate := strings.Join(fqdnParts, ".")
		for _, domain := range domains {
			if candidate == domain {
				return domain, nil
			}
		}
		fqdnParts = fqdnParts[1:] // Remove the left-most segment
	}

	return "", fmt.Errorf("no matching domain found for FQDN: %s", fqdn)
}

// getSecret retrieves the secret value using the provided client, namespace, secret name, and key.
func getSecret(client kubernetes.Interface, namespace, secretName, key string) (string, error) {
	secret, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s in namespace %s: %v", secretName, namespace, err)
	}

	// Extract the value from the secret's data using the key
	valueBytes, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s", key, secretName)
	}

	// Convert the secret data to a string
	return string(valueBytes), nil
}

func fetchDomainName(c *vercelDNSProviderSolver, apiToken string, queryParams map[string]string, fqdn string) (string, error) {
	domains, err := getVercelDomains(c, apiToken, queryParams)
	if err != nil {
		return "", fmt.Errorf("unable to fetch domains from Vercel: %v", err)
	}

	domain, err := matchDomain(fqdn, domains)
	if err != nil {
		return "", err
	}

	return domain, nil
}
