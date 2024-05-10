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
	"os"
	"strings"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

// PodNamespace is the namespace of the webhook pod
var PodNamespace = os.Getenv("POD_NAMESPACE")

// PodSecretName is the name of the secret to obtain the Vercel API token from
var PodSecretName = os.Getenv("POD_SECRET_NAME")

// PodSecretKey is the key of the Vercel API token within the secret POD_SECRET_NAME
var PodSecretKey = os.Getenv("POD_SECRET_KEY")

var Slug = os.Getenv("TEAM_SLUG")
var TeamId = os.Getenv("TEAM_ID")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&vercelDNSProviderSolver{},
	)
}

// vercelDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record to Vercel.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type vercelDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	//client kubernetes.Clientset
	client *kubernetes.Clientset
	ctx    context.Context
}

// vercelDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type vercelDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	//Email           string `json:"email"`
	//APIKeySecretRef v1alpha1.SecretKeySelector `json:"apiKeySecretRef"`
	APIKeySecretRef cmmeta.SecretKeySelector `json:"apiKeySecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *vercelDNSProviderSolver) Name() string {
	return "vercel"
}

func (c *vercelDNSProviderSolver) makeVercelRequest(method, baseURL string, body []byte, apiToken string, queryParams map[string]string) ([]byte, error) {
	// Parse the base URL
	u, err := url.Parse(baseURL)
	if err != nil {
		log.Printf("Error parsing base URL: %v", err)
		return nil, err
	}
	log.Printf("Parsed base URL: %s", u.String())

	// Prepare query parameters
	q := u.Query()
	for key, value := range queryParams {
		if value != "" {
			q.Set(key, value)
		}
	}
	u.RawQuery = q.Encode()

	log.Printf("Final URL with query parameters: %s", u.String())

	req, err := http.NewRequest(method, u.String(), bytes.NewReader(body))
	if err != nil {
		log.Printf("Error creating HTTP request: %v", err)
		return nil, err
	}
	log.Printf("Created HTTP request: %+v", req)

	// Encode the API token before adding it to the header
	token := strings.TrimSpace(apiToken)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	log.Printf("Created HTTP request: %+v", req)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending HTTP request: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	log.Printf("Received HTTP response with status code: %d", resp.StatusCode)

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

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
// func (c *vercelDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
// 	cfg, err := loadConfig(ch.Config)
// 	if err != nil {
// 		return err
// 	}

// 	// TODO: do something more useful with the decoded configuration
// 	fmt.Printf("Decoded configuration %v", cfg)

// 	// TODO: add code that sets a record in the DNS provider's console
// 	return nil
// }

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.vercel.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
// func (c *vercelDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
// 	// TODO: add code that deletes a record from the DNS provider's console
// 	return nil
// }

// getSecret retrieves the secret value using the provided client, namespace, secret name, and key.
func getSecret(client kubernetes.Interface, namespace, secretName, key string) (string, error) {
	println("namespace", namespace)
	println("secretName", secretName)
	println("key", key)
	secret, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s in namespace %s: %v", secretName, namespace, err)
	}

	// Print metadata
	fmt.Printf("Secret Metadata:\n")
	fmt.Printf("Name: %s\n", secret.ObjectMeta.Name)
	fmt.Printf("Namespace: %s\n", secret.ObjectMeta.Namespace)
	fmt.Printf("Labels: %v\n", secret.ObjectMeta.Labels)
	fmt.Printf("Annotations: %v\n", secret.ObjectMeta.Annotations)

	// Print data
	fmt.Printf("Secret Data:\n")
	for key, value := range secret.Data {
		fmt.Printf("%s: %s\n", key, value)
	}

	// Print the entire secret as JSON
	secretJSON, err := json.Marshal(secret)
	if err != nil {
		fmt.Printf("Failed to marshal secret as JSON: %v\n", err)
	}
	fmt.Printf("Secret (JSON):\n%s\n", secretJSON)

	// Extract the value from the secret's data using the key
	valueBytes, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s", key, secretName)
	}

	// Convert the secret data to a string
	return string(valueBytes), nil
}

// getVercelDomains retrieves all domains from Vercel for the account associated with the given API token.
func getVercelDomains(c *vercelDNSProviderSolver, apiToken string) ([]string, error) {
	var domains []string
	url := "https://api.vercel.com/v5/domains"

	println("API TOKEN", apiToken)
	queryParams := map[string]string{
		"slug":   Slug,
		"teamId": TeamId,
	}

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

func (c *vercelDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	fmt.Println("Challenge Request:")
	fmt.Println("Domain:", ch.ResolvedFQDN)
	fmt.Println("Key:", ch.Key)
	fmt.Println("Auth Zone:", ch.ResolvedZone)

	// Print the whole ChallengeRequest struct as JSON
	chJSON, err := json.Marshal(ch)
	if err != nil {
		return err
	}
	fmt.Println("Challenge Request (JSON):", string(chJSON))

	apiToken, err := getSecret(c.client, ch.ResourceNamespace, cfg.APIKeySecretRef.Name, cfg.APIKeySecretRef.Key)
	if err != nil {
		return fmt.Errorf("unable to get API token: %v", err)
	}

	domains, err := getVercelDomains(c, apiToken)
	if err != nil {
		return fmt.Errorf("unable to fetch domains from Vercel: %v", err)
	}

	domain, err := matchDomain(ch.ResolvedFQDN, domains)
	if err != nil {
		return err
	}

	// Here we use fmt.Sprintf to interpolate the domain into the URL
	url := fmt.Sprintf("https://api.vercel.com/v2/domains/%s/records", domain)

	queryParams := map[string]string{
		"slug":   Slug,
		"teamId": TeamId,
	}

	// Define the DNS record
	record := map[string]interface{}{
		"name":    ch.ResolvedFQDN,
		"type":    "TXT",
		"value":   ch.Key,
		"ttl":     60,
		"comment": "Added by rhythmbhiwani/cert-manager-webhook-vercel",
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return err
	}

	_, err = c.makeVercelRequest("POST", url, recordJSON, apiToken, queryParams)
	return err
}

func (c *vercelDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	apiToken, err := getSecret(c.client, ch.ResourceNamespace, cfg.APIKeySecretRef.Name, cfg.APIKeySecretRef.Key)
	if err != nil {
		return fmt.Errorf("unable to get API token: %v", err)
	}

	domains, err := getVercelDomains(c, apiToken)
	if err != nil {
		return fmt.Errorf("unable to fetch domains from Vercel: %v", err)
	}

	domain, err := matchDomain(ch.ResolvedFQDN, domains)
	if err != nil {
		return err
	}

	// Interpolate the domain into the URL
	url := fmt.Sprintf("https://api.vercel.com/v2/domains/%s/records", domain)

	queryParams := map[string]string{
		"slug":   Slug,
		"teamId": TeamId,
	}

	// Fetch all records for the domain
	responseBody, err := c.makeVercelRequest("GET", url, nil, apiToken, queryParams)
	if err != nil {
		return fmt.Errorf("failed to fetch DNS records: %v", err)
	}

	// Parse the response body to find the correct record
	var records struct {
		Records []struct {
			Id    string `json:"id"`
			Name  string `json:"name,omitempty"` // omitempty ensures that empty string values are not marshalled
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"records"`
	}
	if err := json.Unmarshal(responseBody, &records); err != nil {
		return fmt.Errorf("error decoding response JSON: %v", err)
	}

	for _, record := range records.Records {
		fmt.Printf("Record ID: %s\n", record.Id)
		fmt.Printf("Name: %s\n", record.Name)
		fmt.Printf("Type: %s\n", record.Type)
		fmt.Printf("Value: %s\n", record.Value)
		fmt.Println("---------------------------")
	}

	fmt.Println("ch.ResolvedFQDN", ch.ResolvedFQDN)
	fmt.Println("strings.TrimSuffix(ch.ResolvedFQDN, '.')", strings.TrimSuffix(ch.ResolvedFQDN, "."+domain))

	// Find the record ID
	recordID := ""
	for _, record := range records.Records {
		if record.Name == strings.TrimSuffix(ch.ResolvedFQDN, "."+domain+".") && record.Type == "TXT" && record.Value == ch.Key {
			recordID = record.Id
			break
		}
	}

	if recordID == "" {
		return fmt.Errorf("no matching TXT record found for deletion")
	}

	// Delete the identified record
	deleteURL := fmt.Sprintf("%s/%s", url, recordID)
	_, err = c.makeVercelRequest("DELETE", deleteURL, nil, apiToken, queryParams)
	return err
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *vercelDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	///// UNCOMMENT THE BELOW CODE TO MAKE A KUBERNETES CLIENTSET AVAILABLE TO
	///// YOUR CUSTOM DNS PROVIDER

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	///// END OF CODE TO MAKE KUBERNETES CLIENTSET AVAILABLE
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (vercelDNSProviderConfig, error) {
	cfg := vercelDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
