package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// --- Cloud / infrastructure misconfiguration scanner ------------------------
//
// This check looks for the configuration mistakes that turn up on nearly
// every engagement: secrets and version-control metadata left inside the
// web root, administrative APIs (Kubernetes, Docker, Consul, ...) reachable
// without authentication, and object storage exposed to the world.
//
// Everything here is read-only. The OpenAPI/Swagger endpoints are super-wide
// path probes, so the *existence* of a 2xx is never enough — prose hits
// still have to mention OpenAPI/Swagger, and document hits must actually
// parse as a spec. The same "prove it" rule applies to the bucket check:
// a 2xx response is only reported when the body really is a bucket listing.

// cloudSensitivePaths are paths that should never be reachable from a web
// root. Each carries its own severity because losing /.git is not the same
// as losing /.DS_Store.
var cloudSensitivePaths = []struct {
	Path        string
	Severity    model.Severity
	Title       string
	Description string
	Remediation string
}{
	{
		Path:        "/.git/config",
		Severity:    model.SeverityHigh,
		Title:       "Exposed Git metadata (.git/config)",
		Description: "The Git repository's configuration is served from the web root. Anyone can crawl /.git/ (/info/refs, the packfiles, ...) and reconstruct the source tree — including secrets that were committed once and later \"removed\".",
		Remediation: "Deny all access to /.git/ at the web server / reverse proxy / CDN and redeploy from a clean checkout that never contained the repository metadata.",
	},
	{
		Path:        "/.git/HEAD",
		Severity:    model.SeverityHigh,
		Title:       "Exposed Git repository (.git/HEAD)",
		Description: "The Git HEAD reference is publicly readable, confirming the whole .git directory is exposed and can be cloned or scraped for source code and embedded secrets.",
		Remediation: "Block /.git/ entirely and rotate any credential that was ever committed to the repository.",
	},
	{
		Path:        "/.env",
		Severity:    model.SeverityCritical,
		Title:       "Exposed environment file (.env)",
		Description: "A dotenv file is served over HTTP. These routinely hold database passwords, API keys, mail credentials and application secrets in plaintext.",
		Remediation: "Return 404 for dotfiles, move secrets out of the web root, and rotate every credential the file contained (treat them as compromised).",
	},
	{
		Path:        "/.aws/credentials",
		Severity:    model.SeverityCritical,
		Title:       "Exposed AWS credentials file (.aws/credentials)",
		Description: "An AWS shared credentials file is publicly readable, exposing access key IDs and secret access keys for whatever profile it defines.",
		Remediation: "Block access immediately and rotate the exposed IAM credentials; never place cloud credentials inside a served directory.",
	},
	{
		Path:        "/.htpasswd",
		Severity:    model.SeverityHigh,
		Title:       "Exposed password file (.htpasswd)",
		Description: "The HTTP basic-auth password file is readable, leaking usernames and (weakly hashed) passwords that can be cracked offline.",
		Remediation: "Deny access to .ht* files in the web server configuration and rotate the affected password hashes.",
	},
	{
		Path:        "/.DS_Store",
		Severity:    model.SeverityLow,
		Title:       "Exposed macOS metadata (.DS_Store)",
		Description: "A Finder metadata file is served. It leaks the names of files (and sometimes directory structure) that were on the machine at publish time, which is useful reconnaissance for further attacks.",
		Remediation: "Exclude .DS_Store from deployments and add it to the web server's deny list.",
	},
	{
		Path:        "/docker-compose.yml",
		Severity:    model.SeverityHigh,
		Title:       "Exposed docker-compose.yml",
		Description: "A docker-compose definition is publicly readable, typically disclosing service topology, image tags (with versions), bind mounts and inline environment variables (database passwords, API tokens).",
		Remediation: "Remove the file from the web root and rotate any credentials it exposed.",
	},
}

var (
	gitConfigRe      = regexp.MustCompile(`(?im)^\s*\[core\]|repositoryformatversion|filemode\s*=|bare\s*=`)
	gitHeadRe        = regexp.MustCompile(`^ref:\s+refs/`)
	envFileRe        = regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]{2,}\s*=\s*\S`)
	awsCredsRe       = regexp.MustCompile(`(?m)^aws_(access_key_id|secret_access_key)\s*=`)
	htpasswdRe       = regexp.MustCompile(`(?m)^[A-Za-z0-9._-]+:(\$2[aby]\$|\$apr1\$|\{SHA\}|[A-Za-z0-9./]{13}$)`)
	dsStoreMagic     = []byte{0x00, 0x00, 0x00, 0x01, 0x42, 0x75, 0x64, 0x31}
	dockerComposeRe  = regexp.MustCompile(`(?m)^\s*services:\s*$`)
	dockerComposeRe2 = regexp.MustCompile(`(?m)^\s{2,}[A-Za-z0-9_.-]+:\s*$`)
)

// cloudSensitiveMatch is the pure validator behind every file probe above:
// it answers "does this body really look like the artifact we asked for?".
func cloudSensitiveMatch(path, body string, raw []byte) bool {
	switch path {
	case "/.git/config":
		return gitConfigRe.MatchString(body)
	case "/.git/HEAD":
		return gitHeadRe.MatchString(strings.TrimSpace(body)) || strings.Contains(body, "refs/heads/")
	case "/.env":
		return envFileRe.MatchString(body)
	case "/.aws/credentials":
		return awsCredsRe.MatchString(body)
	case "/.htpasswd":
		return htpasswdRe.MatchString(body)
	case "/.DS_Store":
		return len(raw) >= 8 && string(raw[:8]) == string(dsStoreMagic)
	case "/docker-compose.yml":
		return dockerComposeRe.MatchString(body) && dockerComposeRe2.MatchString(body)
	}
	return false
}

// cloudAdminEndpoint is a known administrative API whose responses carry an
// unmistakable signature.
type cloudAdminEndpoint struct {
	Path        string
	Severity    model.Severity
	Title       string
	Description string
	Remediation string
	Marker      func(body string, status int) string
}

var cloudAdminEndpoints = []cloudAdminEndpoint{
	{
		Path:        "/api/v1/namespaces",
		Severity:    model.SeverityCritical,
		Title:       "Unauthenticated Kubernetes API server",
		Description: "The Kubernetes API answered an anonymous request with a namespace listing. An unauthenticated API server means cluster-wide read (and usually write) access, which is effectively game over for every workload it schedules.",
		Remediation: "Enable authentication/authorisation on the API server (never --anonymous-auth=true), restrict network access to the control plane, and audit what the anonymous request already exposed.",
		Marker: func(body string, status int) string {
			if regexp.MustCompile(`"kind"\s*:\s*"NamespaceList"`).MatchString(body) {
				return "NamespaceList"
			}
			if regexp.MustCompile(`"kind"\s*:\s*"Namespace"`).MatchString(body) && strings.Contains(body, `"apiVersion"`) {
				return "\"kind\":\"Namespace\""
			}
			return ""
		},
	},
	{
		Path:        "/version",
		Severity:    model.SeverityHigh,
		Title:       "Unauthenticated Kubernetes /version endpoint",
		Description: "The Kubernetes API server version endpoint answered without credentials, disclosing the exact build (including git version and compiler) — a reliable way to pick known CVEs for the running release.",
		Remediation: "Require authentication for all API server endpoints and keep the control plane off untrusted networks.",
		Marker: func(body string, status int) string {
			re := regexp.MustCompile(`"gitVersion"\s*:\s*"v?\d+\.\d+`)
			return re.FindString(body)
		},
	},
	{
		Path:        "/healthz",
		Severity:    model.SeverityMedium,
		Title:       "Unauthenticated Kubernetes /healthz endpoint",
		Description: "The Kubernetes API server health endpoint is reachable anonymously. On its own it only confirms reachability, but it is the standard first step in fingerprinting an exposed control plane.",
		Remediation: "Restrict access to the API server (network policy, firewall, private endpoint) rather than relying on it merely being \"not too obvious\".",
		Marker: func(body string, status int) string {
			if status == 200 && strings.TrimSpace(body) == "ok" {
				return "body=ok"
			}
			return ""
		},
	},
	{
		Path:        "/v1.24/version",
		Severity:    model.SeverityMedium,
		Title:       "Unauthenticated Kubernetes versioned endpoint (/v1.24/version)",
		Description: "A versioned Kubernetes API endpoint answered anonymously, which both fingerprints the release and confirms the API surface is reachable without credentials.",
		Remediation: "Require authentication on the API server and restrict who can reach its port.",
		Marker: func(body string, status int) string {
			re := regexp.MustCompile(`"gitVersion"\s*:\s*"v?\d+\.\d+`)
			return re.FindString(body)
		},
	},
	{
		Path:        "/api/version",
		Severity:    model.SeverityMedium,
		Title:       "Unauthenticated Docker Engine API version endpoint",
		Description: "The Docker Engine API version endpoint answered anonymously. The Engine API is remote-root-equivalent: whoever can reach it can mount the host filesystem into a container and read or write anything on it.",
		Remediation: "Never expose the Docker socket/API over TCP; bind it to a local socket with filesystem permissions, or front it with authenticated TLS (and verify client certificates).",
		Marker: func(body string, status int) string {
			if regexp.MustCompile(`"ApiVersion"\s*:\s*"|"MinAPIVersion"`).MatchString(body) {
				return "ApiVersion"
			}
			return ""
		},
	},
	{
		Path:        "/v1.41/version",
		Severity:    model.SeverityMedium,
		Title:       "Unauthenticated Docker Engine API versioned endpoint (/v1.41/version)",
		Description: "A versioned Docker Engine endpoint answered anonymously, confirming remote-root-equivalent API access.",
		Remediation: "Bind the Docker API to a Unix socket only, or require authenticated TLS, and remove any TCP exposure.",
		Marker: func(body string, status int) string {
			if regexp.MustCompile(`"ApiVersion"\s*:\s*"`).MatchString(body) {
				return "ApiVersion"
			}
			return ""
		},
	},
	{
		Path:        "/v1/agent/self",
		Severity:    model.SeverityHigh,
		Title:       "Unauthenticated Consul agent API",
		Description: "The Consul agent API answered anonymously, exposing the datacenter name, node name, ACL configuration and member information — the reconnaissance needed to enumerate and pivot through the service mesh.",
		Remediation: "Enable Consul ACLs in default-deny mode, never expose the HTTP API outside the trusted network, and require tokens for all reads.",
		Marker: func(body string, status int) string {
			if strings.Contains(body, `"Config"`) && regexp.MustCompile(`"Datacenter"|"NodeName"`).MatchString(body) {
				return "Config/Datacenter"
			}
			return ""
		},
	},
}

var (
	k8sPodListRe    = regexp.MustCompile(`"kind"\s*:\s*"PodList"`)
	k8sItemsRe      = regexp.MustCompile(`"items"\s*:`)
	consulMembersRe = regexp.MustCompile(`"Members"\s*:|"Datacenter"\s*:`)
	k8sSecretRe     = regexp.MustCompile(`"kind"\s*:\s*"(Secret|SecretList)"`)
)

// cloudAPIPaths is a strong-signature list of API endpoints belonging to
// widely used platforms that must never be reachable anonymously. The
// marker function must match something only the real service returns.
var cloudAPIPaths = []struct {
	Path        string
	Severity    model.Severity
	Title       string
	Description string
	Remediation string
	Marker      func(body string, status int) string
}{
	{
		Path:        "/api/v1/pods",
		Severity:    model.SeverityCritical,
		Title:       "Unauthenticated Kubernetes pod listing",
		Description: "The Kubernetes API returned a pod list to an anonymous caller, disclosing every workload's image, environment variables, volumes and service-account details across the cluster.",
		Remediation: "Enable API server authentication/authorisation and restrict network reachability to the cluster's own components.",
		Marker: func(body string, status int) string {
			if !k8sPodListRe.MatchString(body) || !k8sItemsRe.MatchString(body) {
				return ""
			}
			if strings.Contains(body, `"apiVersion"`) {
				return "PodList"
			}
			return ""
		},
	},
	{
		Path:        "/api/v1/secrets",
		Severity:    model.SeverityCritical,
		Title:       "Unauthenticated Kubernetes secret listing",
		Description: "The Kubernetes API returned a secret list anonymously. Secrets hold credentials, tokens and TLS keys; exposing them lets an attacker impersonate any service in the cluster.",
		Remediation: "Enable RBAC (never grant anonymous access), rotate every secret the endpoint returned, and take the API server off untrusted networks.",
		Marker: func(body string, status int) string {
			if !k8sSecretRe.MatchString(body) {
				return ""
			}
			if strings.Contains(body, `"data"`) || k8sItemsRe.MatchString(body) {
				return "SecretList"
			}
			return ""
		},
	},
	{
		Path:        "/v1/catalog/services",
		Severity:    model.SeverityHigh,
		Title:       "Unauthenticated Consul service catalog",
		Description: "The Consul service catalog answered anonymously, enumerating every registered service, its tags and therefore the internal attack surface.",
		Remediation: "Require ACL tokens for catalog reads and keep the Consul HTTP API on a trusted network only.",
		Marker: func(body string, status int) string {
			re := regexp.MustCompile(`"ServiceName"|^\{[\s\S]*"consul"`)
			if strings.HasPrefix(strings.TrimSpace(body), "{") && (strings.Contains(body, `"ServiceName"`) || strings.Contains(body, `"consul"`)) {
				return "service-catalog-json"
			}
			if re.MatchString(body) {
				return "ServiceName"
			}
			return ""
		},
	},
	{
		Path:        "/v1/status/leader",
		Severity:    model.SeverityLow,
		Title:       "Unauthenticated Consul status endpoint",
		Description: "The Consul status endpoint answered anonymously and disclosed the current leader address — useful for mapping an internal cluster from the outside.",
		Remediation: "Restrict the Consul HTTP API to trusted networks and require tokens for management endpoints.",
		Marker: func(body string, status int) string {
			if regexp.MustCompile(`^\s*"[^"]+:\d+"\s*$`).MatchString(body) {
				return "leader-address"
			}
			return ""
		},
	},
	{
		Path:        "/actuator/env",
		Severity:    model.SeverityCritical,
		Title:       "Exposed Spring Boot Actuator environment (/actuator/env)",
		Description: "The Spring Boot Actuator environment endpoint is exposed, dumping every resolved property — datasource URLs, credentials, API keys and cloud metadata — straight to any anonymous caller.",
		Remediation: "Disable or lock down Actuator endpoints (management.endpoints.web.exposure.include), require authentication, and rotate anything the endpoint disclosed.",
		Marker: func(body string, status int) string {
			if strings.Contains(body, `"propertySources"`) || strings.Contains(body, `"activeProfiles"`) || strings.Contains(body, `"systemProperties"`) {
				return "propertySources"
			}
			return ""
		},
	},
	{
		Path:        "/actuator/health",
		Severity:    model.SeverityLow,
		Title:       "Exposed Spring Boot Actuator health endpoint",
		Description: "The Spring Boot Actuator health endpoint is publicly reachable, disclosing component health (databases, disks, message brokers) that helps map the backend architecture.",
		Remediation: "Expose Actuator endpoints only on an internal management port and require authentication for detail-level responses.",
		Marker: func(body string, status int) string {
			if regexp.MustCompile(`"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE|UNKNOWN)"`).MatchString(body) {
				return `"status"`
			}
			return ""
		},
	},
	{
		Path:        "/swagger.json",
		Severity:    model.SeverityHigh,
		Title:       "Exposed API specification (Swagger/OpenAPI)",
		Description: "The API's own specification was published at the canonical Swagger path, handing an attacker the complete endpoint/parameter inventory of the service.",
		Remediation: "Remove the specification from production, or gate it behind authentication; use it in CI/CD rather than serving it to the world.",
		Marker:      swaggerSpecMarker,
	},
	{
		Path:        "/openapi.json",
		Severity:    model.SeverityHigh,
		Title:       "Exposed API specification (OpenAPI)",
		Description: "The OpenAPI document is served openly, listing every operation, parameter and schema of the API.",
		Remediation: "Publish API documentation internally only, or require authentication to retrieve the specification.",
		Marker:      swaggerSpecMarker,
	},
	{
		Path:        "/api/swagger.json",
		Severity:    model.SeverityHigh,
		Title:       "Exposed API specification (/api/swagger.json)",
		Description: "A Swagger/OpenAPI document is served from the API root, disclosing the full operation inventory.",
		Remediation: "Gate API specifications behind authentication and remove them from production builds.",
		Marker:      swaggerSpecMarker,
	},
	{
		Path:        "/api-docs",
		Severity:    model.SeverityHigh,
		Title:       "Exposed API documentation (/api-docs)",
		Description: "Spring Boot's API documentation endpoint is publicly served, enumerating the application's API surface.",
		Remediation: "Disable springdoc/springfox in production or restrict it behind authentication.",
		Marker:      swaggerSpecMarker,
	},
}

// swaggerSpecMarker requires the response to actually parse as JSON *and*
// carry the swagger/openapi version keys, so an unrelated 200 (an SPA shell
// or a generic error page) can never be reported as a spec disclosure.
func swaggerSpecMarker(body string, status int) string {
	trimmed := strings.TrimSpace(body)
	if !strings.HasPrefix(trimmed, "{") {
		return ""
	}
	var doc map[string]interface{}
	if json.Unmarshal([]byte(body), &doc) != nil {
		return ""
	}
	for _, k := range []string{"swagger", "openapi"} {
		if v, ok := doc[k].(string); ok && isDottedVersion(v) {
			if _, ok := doc["paths"]; ok {
				return k + " " + v
			}
			if _, ok := doc["info"]; ok {
				return k + " " + v
			}
		}
	}
	return ""
}

func isDottedVersion(v string) bool {
	return regexp.MustCompile(`^\d+(\.\d+)+$`).MatchString(strings.TrimSpace(v))
}

// cloudMetadataEndpoints are the cloud instance-metadata services. Reaching
// one from the outside means the environment allows requests to link-local
// addresses (or the app proxies them), which is the classic first step of
// an SSRF-to-credential-theft chain.
var cloudMetadataEndpoints = []struct {
	URL         string
	Severity    model.Severity
	Title       string
	Description string
	Remediation string
}{
	{
		URL:         "http://169.254.169.254/latest/meta-data/",
		Severity:    model.SeverityHigh,
		Title:       "Reachable AWS EC2 instance metadata service",
		Description: "The EC2 instance metadata service answered this scan. If the application (or a proxy in front of it) can reach 169.254.169.254, an SSRF that lands here can steal the instance role's temporary credentials — and with IMDSv1 that needs nothing more than a plain GET.",
		Remediation: "Enforce IMDSv2 (require a token via PUT /latest/api/token and set http_tokens=required), restrict pods/containers from the link-local range, and validate outbound URL destinations in the application.",
	},
	{
		URL:         "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		Severity:    model.SeverityCritical,
		Title:       "AWS instance credentials exposed via metadata",
		Description: "The metadata service returned an IAM role name, meaning a follow-up request to that path yields live AccessKeyId/SecretAccessKey/Token values. Anyone able to make one HTTP request from this host can impersonate the instance role.",
		Remediation: "Require IMDSv2, scope instance roles to least privilege, and block container/pod access to 169.254.169.254.",
	},
	{
		URL:         "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/",
		Severity:    model.SeverityCritical,
		Title:       "Reachable GCP metadata service (service accounts)",
		Description: "The GCP metadata service answered (with the required Metadata-Flavor header). From here /token on a service-account path returns an OAuth access token for that identity.",
		Remediation: "Set metadata hidden, restrict egress to metadata.google.internal, and use workload identity instead of node-level service accounts.",
	},
	{
		URL:         "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		Severity:    model.SeverityHigh,
		Title:       "Reachable Azure IMDS instance metadata",
		Description: "The Azure IMDS endpoint answered (Metadata:true header accepted), confirming instance metadata is reachable — including subscription, resource group and, with a managed identity token request, access tokens.",
		Remediation: "Restrict access to 169.254.169.254 from application workloads and prefer workload identity federation over IMDS-issued tokens.",
	},
	{
		URL:         "http://metadata.google.internal/computeMetadata/v1/project/project-id",
		Severity:    model.SeverityHigh,
		Title:       "Reachable GCP metadata hostname (project-id)",
		Description: "The GCP metadata host answered and disclosed the project id, confirming the instance metadata service is reachable by name (the same path an SSRF payload would take).",
		Remediation: "Hide instance metadata from unprivileged workloads and block egress to metadata.google.internal.",
	},
	{
		URL:         "http://100.100.100.200/latest/meta-data/",
		Severity:    model.SeverityHigh,
		Title:       "Reachable Alibaba Cloud metadata service",
		Description: "The Alibaba Cloud ECS metadata service answered, exposing instance metadata (and with it the instance's RAM role credentials) to anyone who can make one request from this host.",
		Remediation: "Block access to 100.100.100.200 from application code and apply least-privilege RAM roles.",
	},
}

var (
	awsMetadataMarkerRe   = regexp.MustCompile(`(?m)^(ami-id|instance-id|instance-type|placement/|iam/|hostname|public-ipv4|security-groups)`)
	gcpMetadataMarkerRe   = regexp.MustCompile(`^\s*[\w.-]+@[\w.-]+\.gserviceaccount\.com\s*$|^\s*\d+\s*$`)
	azureMetadataMarkerRe = regexp.MustCompile(`"compute"\s*:\s*\{|"subscriptionId"\s*:\s*"`)
	alibabaMarkerRe       = regexp.MustCompile(`(?m)^(instance-id|region-id|zone-id|private-ipv4|image-id)`)
	gcpProjectMarkerRe    = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
)

// cloudMetadataRequest builds the request for one metadata endpoint,
// including the provider-specific header some of them demand (GCP's
// Metadata-Flavor, Azure's Metadata) — without those headers the services
// return 403 even when they *are* reachable, which would hide the finding.
func cloudMetadataRequest(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, targetURL string) *httpclient.Exchange {
	headers := map[string]string{}
	host := ""
	if u, err := url.Parse(targetURL); err == nil {
		host = u.Hostname()
	}
	switch {
	case strings.Contains(targetURL, "computeMetadata"):
		headers["Metadata-Flavor"] = "Google"
	case host == "metadata.google.internal":
		headers["Metadata-Flavor"] = "Google"
	case strings.Contains(targetURL, "169.254.169.254/metadata/instance"):
		headers["Metadata"] = "true"
	}
	if !lim.Acquire(ctx) {
		return &httpclient.Exchange{Err: context.Canceled}
	}
	defer lim.Release()
	ex := cli.Do("GET", targetURL, nil, headers)
	observeForAdaptive(lim, ex)
	return ex
}

// cloudMetadataMarker decides whether a metadata response really came from
// the metadata service (rather than a generic proxy error page).
func cloudMetadataMarker(targetURL, body string, status int) string {
	if status < 200 || status >= 300 {
		return ""
	}
	switch {
	case strings.Contains(targetURL, "iam/security-credentials"):
		if strings.TrimSpace(body) != "" && !strings.Contains(strings.ToLower(body), "<html") {
			return strings.TrimSpace(firstLine(body))
		}
	case strings.Contains(targetURL, "computeMetadata") || strings.Contains(targetURL, "metadata.google.internal"):
		if m := gcpMetadataMarkerRe.FindString(body); m != "" {
			return strings.TrimSpace(m)
		}
		if strings.Contains(targetURL, "project-id") && gcpProjectMarkerRe.MatchString(strings.TrimSpace(body)) {
			return strings.TrimSpace(body)
		}
	case strings.Contains(targetURL, "169.254.169.254/metadata/instance"):
		if m := azureMetadataMarkerRe.FindString(body); m != "" {
			return m
		}
	case strings.Contains(targetURL, "100.100.100.200"):
		if m := alibabaMarkerRe.FindString(body); m != "" {
			return m
		}
	default:
		if m := awsMetadataMarkerRe.FindString(body); m != "" {
			return m
		}
	}
	return ""
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	if len(s) > 120 {
		return s[:120]
	}
	return s
}

// s3BucketNameRe is a deliberately strict bucket-name pattern: 3–63
// characters, lowercase alphanumerics and hyphens/dots only. Anything else
// is not a plausible bucket name and must never be turned into a URL.
var s3BucketNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// s3ListBucketRe matches the XML root of a real S3 ListBucketResult.
var s3ListBucketRe = regexp.MustCompile(`(?is)<ListBucketResult[\s>]|<Contents[\s>]|<Name>[^<]+</Name>\s*<Prefix`)

// s3BucketRegionRe extracts the bucket's region from the ListBucketResult
// (used only for evidence text).
var s3BucketRegionRe = regexp.MustCompile(`(?is)<BucketRegion>([^<]+)</BucketRegion>`)

// s3NonBucketHints are substrings that mark an AWS service hostname or a
// signed URL rather than a bucket. Reporting any of these as a "public
// bucket" would be noise, so a name containing one is rejected outright.
var s3NonBucketHints = []string{
	"amazonaws.com", "cloudfront.net", "elb.amazonaws", "execute-api",
	".s3-accesspoint", "xl.amazonaws",
}

// looksLikeBucketName reports whether a host label is plausibly an S3
// bucket name (not an AWS service hostname, not a signed URL host).
func looksLikeBucketName(name string) bool {
	low := strings.ToLower(strings.TrimSpace(name))
	if !s3BucketNameRe.MatchString(low) {
		return false
	}
	if strings.Contains(low, "..") || strings.HasPrefix(low, ".") || strings.HasSuffix(low, ".") {
		return false
	}
	for _, hint := range s3NonBucketHints {
		if strings.Contains(low, hint) {
			return false
		}
	}
	return true
}

// extractBucketNames pulls plausible S3 bucket names out of the URLs the
// scan already discovered (virtual-hosted-style hostnames and
// path-style/other URLs' path segments).
func extractBucketNames(targets []model.Target) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || seen[name] || !looksLikeBucketName(name) {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	for _, t := range targets {
		u, err := url.Parse(t.URL)
		if err != nil || u.Host == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if strings.HasSuffix(host, ".s3.amazonaws.com") {
			add(strings.TrimSuffix(host, ".s3.amazonaws.com"))
		}
		if idx := strings.Index(host, ".s3."); idx > 0 && strings.HasSuffix(host, "amazonaws.com") {
			add(host[:idx])
		}
		if strings.HasSuffix(host, ".s3-website") {
			if idx := strings.Index(host, ".s3-website"); idx > 0 {
				add(host[:idx])
			}
		}
		// path-style: https://s3.amazonaws.com/bucket/key
		if strings.HasPrefix(host, "s3.") || host == "s3.amazonaws.com" {
			segs := strings.Split(strings.Trim(u.Path, "/"), "/")
			if len(segs) > 0 {
				add(segs[0])
			}
		}
	}
	sort.Strings(out)
	if len(out) > 5 {
		out = out[:5] // bounded: a scan shouldn't enumerate a whole account
	}
	return out
}

// s3BucketPublic probes the conventional S3 endpoints for a bucket and
// reports it only when the response body is a genuine ListBucketResult
// (an unauthenticated listing), never merely because the status was 2xx.
func s3BucketPublic(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, bucket string, origin string) *model.Finding {
	urls := []string{
		"https://" + bucket + ".s3.amazonaws.com/?max-keys=10",
		"https://s3.amazonaws.com/" + bucket + "/?max-keys=10",
	}
	var lastEx *httpclient.Exchange
	for _, u := range urls {
		if !lim.Acquire(ctx) {
			return nil
		}
		ex := cli.Do("GET", u, nil, nil)
		observeForAdaptive(lim, ex)
		lim.Release()
		if ex.Err != nil || ex.Response == nil {
			continue
		}
		lastEx = ex
		if ex.Response.StatusCode != 200 {
			continue
		}
		if !s3ListBucketRe.MatchString(ex.Body) {
			continue // 2xx but not a bucket listing: an error page or an XML API response — not our finding
		}
		region := ""
		if m := s3BucketRegionRe.FindStringSubmatch(ex.Body); len(m) == 2 {
			region = m[1]
		}
		notes := fmt.Sprintf("Bucket %q returned an unauthenticated ListBucketResult (public ObjectListing).", bucket)
		if region != "" {
			notes += " Bucket region: " + region + "."
		}
		return &model.Finding{
			Category:    "Cloud Misconfiguration",
			Severity:    model.SeverityHigh,
			Title:       fmt.Sprintf("Publicly listable S3 bucket: %s", bucket),
			Description: fmt.Sprintf("The S3 bucket %q serves an unauthenticated bucket listing, so every object key (and, for objects that are also public, their contents) can be enumerated and downloaded. Bucket ACLs or bucket policies are granting public read to ListBucket.", bucket),
			URL:         urls[0],
			Method:      "GET",
			Evidence:    model.Evidence{RequestRaw: lastEx.RequestRaw, ResponseRaw: lastEx.ResponseRaw, Notes: notes + " Discovered from " + origin + "."},
			Remediation: "Remove public read from the bucket ACL/policy (enable Block Public Access and S3 Public Access Block at the account level), serve objects through CloudFront with signed URLs, and audit what was exposed for as long as it was public.",
		}
	}
	return nil
}

// RunCloudMisconfigChecks probes every discovered origin for exposed
// secrets/version-control metadata, unauthenticated administrative APIs and
// reachable cloud metadata services, and checks any S3 bucket the crawl
// referenced for public listing.
func RunCloudMisconfigChecks(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, targets []model.Target) []model.Finding {
	origins := uniqueOrigins(targets)
	if len(origins) == 0 {
		return nil
	}

	type probe struct {
		base string
		path string
	}
	var probes []probe
	for _, o := range origins {
		for _, p := range cloudSensitivePaths {
			probes = append(probes, probe{base: o, path: p.Path})
		}
		for _, p := range cloudAdminEndpoints {
			probes = append(probes, probe{base: o, path: p.Path})
		}
		for _, p := range cloudAPIPaths {
			probes = append(probes, probe{base: o, path: p.Path})
		}
	}

	var mu sync.Mutex
	var findings []model.Finding
	var wg sync.WaitGroup

	for _, pr := range probes {
		pr := pr
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !lim.Acquire(ctx) {
				return
			}
			ex := cli.Get(pr.base + pr.path)
			observeForAdaptive(lim, ex)
			lim.Release()
			if ex.Err != nil || ex.Response == nil {
				return
			}
			status := ex.Response.StatusCode
			if status < 200 || status >= 300 {
				return
			}
			f := cloudProbeFinding(pr.base, pr.path, ex, status)
			if f == nil {
				return
			}
			mu.Lock()
			findings = append(findings, *f)
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Cloud metadata services: these are host-level checks, so once per scan.
	for _, me := range cloudMetadataEndpoints {
		me := me
		if !lim.Acquire(ctx) {
			continue
		}
		ex := cloudMetadataRequest(ctx, lim, cli, me.URL)
		lim.Release()
		if ex == nil || ex.Err != nil || ex.Response == nil {
			continue
		}
		if marker := cloudMetadataMarker(me.URL, ex.Body, ex.Response.StatusCode); marker != "" {
			findings = append(findings, model.Finding{
				Category:    "Cloud Misconfiguration",
				Severity:    me.Severity,
				Title:       me.Title,
				Description: me.Description,
				URL:         me.URL,
				Method:      "GET",
				Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Matched metadata marker: " + marker},
				Remediation: me.Remediation,
			})
		}
	}

	// S3 buckets referenced anywhere in the discovered URL set.
	origin := origins[0]
	for _, bucket := range extractBucketNames(targets) {
		if f := s3BucketPublic(ctx, lim, cli, bucket, origin); f != nil {
			findings = append(findings, *f)
		}
	}

	return findings
}

// cloudProbeFinding turns a 2xx probe response into a finding, applying the
// artifact-specific validator so a catch-all 200 page can't produce a
// false positive. Returns nil when the response doesn't really match.
func cloudProbeFinding(origin, path string, ex *httpclient.Exchange, status int) *model.Finding {
	fullURL := origin + path

	for _, p := range cloudSensitivePaths {
		if p.Path != path {
			continue
		}
		if !cloudSensitiveMatch(path, ex.Body, []byte(ex.Body)) {
			return nil
		}
		return &model.Finding{
			Category:    "Cloud Misconfiguration",
			Severity:    p.Severity,
			Title:       p.Title,
			Description: p.Description,
			URL:         fullURL,
			Method:      "GET",
			Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Matched artifact signature for " + path + "."},
			Remediation: p.Remediation,
		}
	}

	for _, p := range cloudAdminEndpoints {
		if p.Path != path {
			continue
		}
		marker := p.Marker(ex.Body, status)
		if marker == "" {
			return nil
		}
		return &model.Finding{
			Category:    "Cloud Misconfiguration",
			Severity:    p.Severity,
			Title:       p.Title,
			Description: p.Description,
			URL:         fullURL,
			Method:      "GET",
			Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Matched service signature: " + marker},
			Remediation: p.Remediation,
		}
	}

	for _, p := range cloudAPIPaths {
		if p.Path != path {
			continue
		}
		marker := p.Marker(ex.Body, status)
		if marker == "" {
			return nil
		}
		return &model.Finding{
			Category:    "Cloud Misconfiguration",
			Severity:    p.Severity,
			Title:       p.Title,
			Description: p.Description,
			URL:         fullURL,
			Method:      "GET",
			Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Matched service signature: " + marker},
			Remediation: p.Remediation,
		}
	}

	return nil
}

// uniqueOrigins returns the distinct scheme://host of every parsed target,
// sorted for deterministic probing order. The list is capped so a crawl of
// a large estate doesn't turn this check into a heavy sweep.
func uniqueOrigins(targets []model.Target) []string {
	set := map[string]bool{}
	for _, t := range targets {
		if o := schemeHostOf(t.URL); o != "" {
			set[o] = true
		}
	}
	out := make([]string, 0, len(set))
	for o := range set {
		out = append(out, o)
	}
	sort.Strings(out)
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}
