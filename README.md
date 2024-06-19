# Cert-Manager ACME DNS01 Webhook Solver for Vercel DNS Manager

[![Go Report Card](https://goreportcard.com/badge/github.com/rhythmbhiwani/cert-manager-webhook-vercel)](https://goreportcard.com/report/github.com/rhythmbhiwani/cert-manager-webhook-vercel)
[![Releases](https://img.shields.io/github/v/release/rhythmbhiwani/cert-manager-webhook-vercel?include_prereleases)](https://github.com/rhythmbhiwani/cert-manager-webhook-vercel/releases)
[![LICENSE](https://img.shields.io/github/license/rhythmbhiwani/cert-manager-webhook-vercel)](https://github.com/rhythmbhiwani/cert-manager-webhook-vercel/blob/master/LICENSE)

A webhook to use [Vercel DNS Manager](https://vercel.com/docs/projects/domains) as a DNS01
ACME Issuer for [cert-manager](https://github.com/jetstack/cert-manager).

## Installation

```bash
helm install cert-manager-webhook-vercel \
  --namespace cert-manager \
  https://github.com/rhythmbhiwani/cert-manager-webhook-vercel/releases/download/cert-manager-webhook-vercel-v1.0.1/cert-manager-webhook-vercel-v1.0.1.tgz
```

## Usage

### Create Vercel API Token Secret

Get your vercel token from https://vercel.com/account/tokens with proper scope

```bash
kubectl create secret generic vercel-credentials \
  --namespace=cert-manager \
  --from-literal=token=<VERCEL TOKEN>
```

### Create Issuer

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    email: example@example.com
    privateKeySecretRef:
      name: letsencrypt-staging
    solvers:
      - dns01:
          cnameStrategy: Follow
          webhook:
            config:
              apiKeySecretRef:
                key: token
                name: vercel-credentials
              teamId: ""
              teamSlug: ""
            groupName: acme.rhythmbhiwani.in
            solverName: vercel
```

Fill appropriate details above in the config. If your domains are under specific team, you can enter their `teamId` or `teamSlug` or both.

If your domains are not using `CNAME`, then you can remove the line `cnameStrategy: Follow`.

## Development

### Running the test suite

Conformance testing is achieved through Kubernetes emulation via the
kubebuilder-tools suite, in conjunction with real calls to the Vercel API on an
test domain, using a valid API token.

The test configures a cert-manager-dns01-tests TXT entry, attempts to verify its
presence, and removes the entry, thereby verifying the Prepare and CleanUp
functions.

Run the test suite with:

```bash
export VERCEL_TOKEN=$(echo -n "<your API token>" | base64 -w 0)
envsubst < testdata/vercel/secret.yaml.example > testdata/vercel/secret.yaml
TEST_ZONE_NAME=yourdomain.com. make test
```
