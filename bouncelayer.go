package bouncelayer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Client struct {
	APIKey     string
	BaseURL    string
	HTTPClient *http.Client
}

func NewClient(apiKey string) *Client {
	if apiKey == "" {
		apiKey = os.Getenv("BOUNCELAYER_API_KEY")
	}
	return &Client{
		APIKey:  apiKey,
		BaseURL: "https://api.bouncelayer.com/v1",
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

type VerificationResult struct {
	Email              string `json:"email"`
	Status             string `json:"status"`
	IsValid            bool   `json:"is_valid"`
	SyntaxValid        bool   `json:"syntax_valid"`
	Domain             string `json:"domain"`
	DomainValid        bool   `json:"domain_valid"`
	HasMX              bool   `json:"has_mx"`
	IsDisposable       bool   `json:"is_disposable"`
	IsRoleBased        bool   `json:"is_role_based"`
	IsCatchAll         bool   `json:"is_catch_all"`
	IsFreeProvider     bool   `json:"is_free_provider"`
	// DidYouMean is a suggested fix for a mistyped domain. It never changes Status.
	DidYouMean         *string `json:"did_you_mean,omitempty"`
	// Explanation is a plain-English reason for the result.
	Explanation        *string `json:"explanation,omitempty"`
	ConfidenceScore    int    `json:"confidence_score"`
	StatusReason       string `json:"status_reason"`
	Provider           string `json:"provider"`
	VerificationTimeMs int    `json:"verification_time_ms"`
	Cached             bool   `json:"cached"`
	SMTPChecked        bool   `json:"smtp_checked"`
	SMTPResponseCode   *int   `json:"smtp_response_code,omitempty"`
}

type SingleVerifyResponse struct {
	Success     bool               `json:"success"`
	CreditsUsed int                `json:"credits_used"`
	Result      VerificationResult `json:"result"`
}

type BulkSubmitResponse struct {
	Success         bool   `json:"success"`
	JobID           string `json:"job_id"`
	TotalEmails     int    `json:"total_emails"`
	Status          string `json:"status"`
	CreditsReserved int    `json:"credits_reserved"`
}

type BulkJobStatus struct {
	JobID           string               `json:"job_id"`
	Status          string               `json:"status"`
	TotalEmails     int                  `json:"total_emails"`
	ProcessedEmails int                  `json:"processed_emails"`
	ValidCount      int                  `json:"valid_count"`
	InvalidCount    int                  `json:"invalid_count"`
	CreditsUsed     int                  `json:"credits_used"`
	CreatedAt       string               `json:"created_at"`
	Results         []VerificationResult `json:"results,omitempty"`
}

func (c *Client) doRequest(method, endpoint string, body interface{}, out interface{}) error {
	if c.APIKey == "" {
		return errors.New("bouncelayer: missing API key")
	}

	url := fmt.Sprintf("%s%s", strings.TrimRight(c.BaseURL, "/"), endpoint)
	var bodyReader io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewBuffer(jsonBytes)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return err
	}

	req.Header.Set("X-API-Key", c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "BounceLayer-Go-SDK/1.0.0")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		respBytes, _ := io.ReadAll(res.Body)
		return fmt.Errorf("bouncelayer: API error (status %d): %s", res.StatusCode, string(respBytes))
	}

	return json.NewDecoder(res.Body).Decode(out)
}

// VerifySingle checks one email address in real-time.
func (c *Client) VerifySingle(email string) (*VerificationResult, error) {
	var resp SingleVerifyResponse
	err := c.doRequest("POST", "/verify/single", map[string]string{"email": email}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp.Result, nil
}

// VerifyBulk submits a list of emails for batch processing.
func (c *Client) VerifyBulk(emails []string, webhookURL string) (*BulkSubmitResponse, error) {
	payload := map[string]interface{}{"emails": emails}
	if webhookURL != "" {
		payload["webhook_url"] = webhookURL
	}
	var resp BulkSubmitResponse
	err := c.doRequest("POST", "/verify/bulk", payload, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetBulkJob queries the current status of a bulk verification job.
func (c *Client) GetBulkJob(jobID string) (*BulkJobStatus, error) {
	var resp BulkJobStatus
	err := c.doRequest("GET", fmt.Sprintf("/verify/bulk/%s", jobID), nil, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// VerifyWebhookSignature verifies cryptographic HMAC-SHA256 signature from BounceLayer webhooks.
func VerifyWebhookSignature(payload []byte, signatureHeader, secret string) bool {
	cleanSig := strings.TrimPrefix(signatureHeader, "sha256=")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(cleanSig))
}
