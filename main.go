package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

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
	TeamSlug        string                   `json:"teamSlug,omitempty"`
	TeamId          string                   `json:"teamId,omitempty"`
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

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *vercelDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.V(6).Infof("Presented with challenge for fqdn=%s zone=%s", ch.ResolvedFQDN, ch.ResolvedZone)

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	var queryParams = map[string]string{
		"slug":   cfg.TeamSlug,
		"teamId": cfg.TeamId,
	}

	apiToken, err := getSecret(c.client, ch.ResourceNamespace, cfg.APIKeySecretRef.Name, cfg.APIKeySecretRef.Key)
	if err != nil {
		return fmt.Errorf("unable to get API token: %v", err)
	}

	domain, err := fetchDomainName(c, apiToken, queryParams, ch.ResolvedFQDN)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://api.vercel.com/v2/domains/%s/records", domain)

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

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.vercel.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *vercelDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	var queryParams = map[string]string{
		"slug":   cfg.TeamSlug,
		"teamId": cfg.TeamId,
	}

	apiToken, err := getSecret(c.client, ch.ResourceNamespace, cfg.APIKeySecretRef.Name, cfg.APIKeySecretRef.Key)
	if err != nil {
		return fmt.Errorf("unable to get API token: %v", err)
	}

	domain, err := fetchDomainName(c, apiToken, queryParams, ch.ResolvedFQDN)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://api.vercel.com/v2/domains/%s/records", domain)

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
