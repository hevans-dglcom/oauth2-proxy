package providers

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/bitly/go-simplejson"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
)

// AzureProvider represents an Azure based Identity Provider
type AzureProvider struct {
	*ProviderData
	Tenant                             string
	GroupField                         string
	isV2Endpoint                       bool
	MicrosoftGraphAccessToken          string
	MicrosoftGraphAccessTokenExpiresOn *time.Time
}

var _ Provider = (*AzureProvider)(nil)

const (
	azureProviderName      = "Azure"
	azureDefaultScope      = "openid"
	azureDefaultGroupField = "id"
)

var (
	// Default Login URL for Azure.
	// Pre-parsed URL of https://login.microsoftonline.com/common/oauth2/authorize.
	azureDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "login.microsoftonline.com",
		Path:   "/common/oauth2/authorize",
	}

	// Default Redeem URL for Azure.
	// Pre-parsed URL of https://login.microsoftonline.com/common/oauth2/token.
	azureDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "login.microsoftonline.com",
		Path:   "/common/oauth2/token",
	}

	// Default Profile URL for Azure.
	// Pre-parsed URL of https://graph.microsoft.com/v1.0/me.
	azureDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "graph.microsoft.com",
		Path:   "/v1.0/me",
	}

	// Default ProtectedResource URL for Azure.
	// Pre-parsed URL of https://graph.microsoft.com.
	azureGraphURL = &url.URL{
		Scheme: "https",
		Host:   "graph.microsoft.com",
		Path:   ".default",
	}
)

// NewAzureProvider initiates a new AzureProvider
func NewAzureProvider(p *ProviderData, opts options.AzureOptions) *AzureProvider {
	p.setProviderDefaults(providerDefaults{
		name:        azureProviderName,
		loginURL:    azureDefaultLoginURL,
		redeemURL:   azureDefaultRedeemURL,
		profileURL:  azureDefaultProfileURL,
		validateURL: nil,
		scope:       azureDefaultScope,
	})

	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}
	p.getAuthorizationHeaderFunc = makeAzureHeader

	tenant := "common"
	if opts.Tenant != "" {
		tenant = opts.Tenant
		p.LoginURL = overrideTenantURL(p.LoginURL, azureDefaultLoginURL, tenant, "authorize")
		p.RedeemURL = overrideTenantURL(p.RedeemURL, azureDefaultRedeemURL, tenant, "token")
	}

	groupField := azureDefaultGroupField
	if opts.GroupField != "" {
		groupField = opts.GroupField
	}

	isV2Endpoint := false
	if strings.Contains(p.LoginURL.String(), "v2.0") {
		isV2Endpoint = true
	}

	return &AzureProvider{
		ProviderData: p,
		Tenant:       tenant,
		GroupField:   groupField,
		isV2Endpoint: isV2Endpoint,
	}
}

func overrideTenantURL(current, defaultURL *url.URL, tenant, path string) *url.URL {
	if current == nil || current.String() == "" || current.String() == defaultURL.String() {
		b := &url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   "/" + tenant + "/oauth2/" + path}

		return b
	}

	return current
}

func getMicrosoftGraphURL(user string) *url.URL {
	return &url.URL{
		Scheme:   "https",
		Host:     "graph.microsoft.com",
		Path:     "/v1.0/users/" + user + "/transitiveMemberOf",
		RawQuery: "$select=displayName,id",
	}
}

func (p *AzureProvider) GetLoginURL(redirectURI, state, _ string, extraParams url.Values) string {
	// In azure oauth v2 there is no resource param
	// https://docs.microsoft.com/en-us/azure/active-directory/azuread-dev/azure-ad-endpoint-comparison#scopes-not-resources
	if p.isV2Endpoint {
		// In azure oauth v2 there is no groups scope so replace it if exists
		p.Scope = strings.ReplaceAll(p.Scope, " groups", "")
	}
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		if p.isV2Endpoint {
			if !strings.Contains(p.Scope, p.ProtectedResource.String()) {
				// protected resource if configured will be added as scope
				p.Scope += " " + p.ProtectedResource.String()
			}
		} else {
			extraParams.Add("resource", p.ProtectedResource.String())
		}
	}
	a := makeLoginURL(p.ProviderData, redirectURI, state, extraParams)
	return a.String()
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *AzureProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*sessions.SessionState, error) {
	params, err := p.prepareRedeem(redirectURL, code, codeVerifier)
	if err != nil {
		return nil, err
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresOn    int64  `json:"expires_on,string"`
		IDToken      string `json:"id_token"`
	}

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return nil, err
	}

	session := &sessions.SessionState{
		AccessToken:  jsonResponse.AccessToken,
		IDToken:      jsonResponse.IDToken,
		RefreshToken: jsonResponse.RefreshToken,
		ProviderID:   p.ProviderID,
	}
	session.CreatedAtNow()
	session.SetExpiresOn(time.Unix(jsonResponse.ExpiresOn, 0))

	err = p.extractClaimsIntoSession(ctx, session)

	if err != nil {
		logger.Printf("unable to get email and/or groups claims from token: %v", err)
	}

	return session, err
}

// EnrichSession enriches the session state with userID, mail and groups
func (p *AzureProvider) EnrichSession(ctx context.Context, session *sessions.SessionState) error {
	err := p.extractClaimsIntoSession(ctx, session)

	if err != nil {
		logger.Printf("unable to get email and/or groups claims from token: %v", err)
	}

	if session.Email == "" {
		email, err := p.getEmailFromProfileAPI(ctx, session.AccessToken)
		if err != nil {
			return fmt.Errorf("unable to get email address from profile URL: %v", err)
		}
		session.Email = email
	}

	// If using the v2.0 oidc endpoint we're also querying Microsoft Graph
	if p.isV2Endpoint {
		groups, err := p.getGroupsFromMicrosoftGraphAPI(ctx, session)
		if err != nil {
			return fmt.Errorf("unable to get groups from Microsoft Graph: %v", err)
		}
		session.Groups = util.RemoveDuplicateStr(append(session.Groups, groups...))
	}
	return nil
}

func (p *AzureProvider) prepareRedeem(redirectURL, code, codeVerifier string) (url.Values, error) {
	params := url.Values{}
	if code == "" {
		return params, ErrMissingCode
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return params, err
	}

	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if codeVerifier != "" {
		params.Add("code_verifier", codeVerifier)
	}

	// In azure oauth v2 there is no resource param
	// https://docs.microsoft.com/en-us/azure/active-directory/azuread-dev/azure-ad-endpoint-comparison#scopes-not-resources
	if p.isV2Endpoint {
		// In azure oauth v2 there is no groups scope so replace it if exists
		p.Scope = strings.ReplaceAll(p.Scope, " groups", "")
	}

	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		if p.isV2Endpoint {
			if !strings.Contains(p.Scope, p.ProtectedResource.String()) {
				// protected resource if configured will be added as scope
				p.Scope += " " + p.ProtectedResource.String()
			}
		} else {
			params.Add("resource", p.ProtectedResource.String())
		}
	}

	return params, nil
}

// extractClaimsIntoSession tries to extract email and groups claims from either id_token or access token
// when oidc verifier is configured
func (p *AzureProvider) extractClaimsIntoSession(ctx context.Context, session *sessions.SessionState) error {

	var innerErr error
	var s *sessions.SessionState

	// First let's verify session token
	err := p.verifySessionToken(ctx, session)
	if err == nil {
		// https://github.com/oauth2-proxy/oauth2-proxy/pull/914#issuecomment-782285814
		// https://github.com/AzureAD/azure-activedirectory-library-for-java/issues/117
		// due to above issues, id_token may not be signed by AAD
		// in that case, we will fallback to access token
		s, innerErr = p.buildSessionFromClaims(session.IDToken, session.AccessToken)
		if innerErr != nil || s.Email == "" {
			s, innerErr = p.buildSessionFromClaims(session.AccessToken, session.AccessToken)
		}

		if innerErr != nil {
			err = fmt.Errorf("unable to get claims from token: %v", innerErr)
		} else {
			session.Email = s.Email
			if s.Groups != nil {
				session.Groups = s.Groups
			}
		}
	} else {
		err = fmt.Errorf("unable to verify token: %v", err)
	}

	return err
}

// verifySessionToken tries to validate id_token if present or access token when oidc verifier is configured
func (p *AzureProvider) verifySessionToken(ctx context.Context, session *sessions.SessionState) error {
	var err error = nil
	if p.Verifier != nil {
		if session.IDToken != "" {
			if _, err = p.Verifier.Verify(ctx, session.IDToken); err != nil {
				logger.Printf("unable to verify ID token, fallback to access token: %v", err)
				_, err = p.Verifier.Verify(ctx, session.AccessToken)
			}
			return err
		}
		_, err = p.Verifier.Verify(ctx, session.AccessToken)
	}
	return err
}

// RefreshSession uses the RefreshToken to fetch new Access and ID Tokens
func (p *AzureProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || s.RefreshToken == "" {
		return false, nil
	}

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	return true, nil
}

func (p *AzureProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) error {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
	}

	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("refresh_token", s.RefreshToken)
	params.Add("grant_type", "refresh_token")

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresOn    int64  `json:"expires_on,string"`
		IDToken      string `json:"id_token"`
	}

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return err
	}

	s.AccessToken = jsonResponse.AccessToken
	s.IDToken = jsonResponse.IDToken
	s.RefreshToken = jsonResponse.RefreshToken

	s.CreatedAtNow()
	s.SetExpiresOn(time.Unix(jsonResponse.ExpiresOn, 0))

	err = p.extractClaimsIntoSession(ctx, s)

	if err != nil {
		logger.Printf("unable to get email and/or groups claims from token: %v", err)
	}

	return nil
}

func makeAzureHeader(accessToken string) http.Header {
	return makeAuthorizationHeader(tokenTypeBearer, accessToken, nil)
}

func (p *AzureProvider) acquireMicrosoftGraphToken(ctx context.Context) error {

	cred, err := confidential.NewCredFromSecret(p.ClientSecret)
	if err != nil {
		return err
	}
	app, err := confidential.New(p.ClientID, cred, confidential.WithAuthority(p.LoginURL.String()))
	if err != nil {
		return err
	}

	var result confidential.AuthResult

	if p.MicrosoftGraphAccessToken == "" {
		result, err = app.AcquireTokenByCredential(ctx, []string{"openid", "email", "profile", azureGraphURL.String()})
		p.MicrosoftGraphAccessToken = result.AccessToken
		p.MicrosoftGraphAccessTokenExpiresOn = &result.ExpiresOn

	} else if p.MicrosoftGraphAccessTokenExpiresOn != nil && !p.MicrosoftGraphAccessTokenExpiresOn.IsZero() && p.MicrosoftGraphAccessTokenExpiresOn.Before(time.Now()) {
		result, err = app.AcquireTokenSilent(ctx, []string{azureGraphURL.String()})
		if err != nil {
			result, err = app.AcquireTokenByCredential(ctx, []string{azureGraphURL.String()})
		}
		p.MicrosoftGraphAccessToken = result.AccessToken
		p.MicrosoftGraphAccessTokenExpiresOn = &result.ExpiresOn
	}
	if err != nil {
		return err
	}
	return nil
}

func (p *AzureProvider) getGroupsFromMicrosoftGraphAPI(ctx context.Context, s *sessions.SessionState) ([]string, error) {

	if err := p.acquireMicrosoftGraphToken(ctx); err != nil {
		return nil, err
	}

	var groupURL = getMicrosoftGraphURL(s.Email).String()
	var groups []string

	for groupURL != "" {
		// logger.Printf("Calling Group API: %s", groupURL)
		jsonRequest, err := requests.New(groupURL).
			WithContext(ctx).
			WithHeaders(makeAzureHeader(p.MicrosoftGraphAccessToken)).
			Do().
			UnmarshalJSON()
		if err != nil {
			return nil, err
		}
		groupURL, err = jsonRequest.Get("@odata.nextLink").String()
		if err != nil {
			groupURL = ""
		}
		groupsPage, err := getGroupsFromJSON(jsonRequest, p.GroupField)
		if err != nil {
			return nil, err
		}
		groups = append(groups, groupsPage...)
	}

	return groups, nil
}

func getGroupsFromJSON(json *simplejson.Json, groupField string) ([]string, error) {
	var groups []string
	for _, doc := range json.Get("value").MustArray() {
		for k, v := range doc.(map[string]interface{}) {
			if k == groupField {
				groups = append(groups, v.(string))
			}
		}
	}
	return groups, nil
}

func (p *AzureProvider) getEmailFromProfileAPI(ctx context.Context, accessToken string) (string, error) {
	if accessToken == "" {
		return "", fmt.Errorf("missing access token")
	}

	json, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeAzureHeader(accessToken)).
		Do().
		UnmarshalJSON()
	if err != nil {
		return "", err
	}

	email, err := getEmailFromJSON(json)
	if email == "" && err == nil {
		err = fmt.Errorf("empty email address: %v", err)
	}
	return email, err
}

func getEmailFromJSON(json *simplejson.Json) (string, error) {
	var email string
	var err error

	email, err = json.Get("mail").String()

	if err != nil || email == "" {
		otherMails, otherMailsErr := json.Get("otherMails").Array()
		if len(otherMails) > 0 {
			email = otherMails[0].(string)
		}
		err = otherMailsErr
	}

	if err != nil || email == "" {
		email, err = json.Get("userPrincipalName").String()
		if err != nil {
			logger.Errorf("unable to find userPrincipalName: %s", err)
			return "", err
		}
	}

	return email, err
}

// ValidateSession validates the AccessToken
func (p *AzureProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeAzureHeader(s.AccessToken))
}
