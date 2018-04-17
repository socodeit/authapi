package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/oauth2"
	"github.com/socodeit/authapi"
	"github.com/socodeit/authapi/internal/response"
)

var (
	errOAuthStateValidation = errors.New("Could not validate oauth2 state param")
)

// OAuth2 module
type OAuth2 struct {
	*authapi.Authapi
}

func init() {
	authapi.RegisterModule("oauth2", &OAuth2{})
}

// Initialize module
func (o *OAuth2) Initialize(ab *authapi.Authapi) error {
	o.Authapi = ab
	if o.OAuth2Storer == nil && o.OAuth2StoreMaker == nil {
		return errors.New("oauth2: need an OAuth2Storer")
	}
	return nil
}

// Routes for module
func (o *OAuth2) Routes() authapi.RouteTable {
	routes := make(authapi.RouteTable)

	for prov, cfg := range o.OAuth2Providers {
		prov = strings.ToLower(prov)

		init := fmt.Sprintf("/oauth2/%s", prov)
		callback := fmt.Sprintf("/oauth2/callback/%s", prov)

		routes[init] = o.oauthInit
		routes[callback] = o.oauthCallback

		if len(o.MountPath) > 0 {
			callback = path.Join(o.MountPath, callback)
		}

		cfg.OAuth2Config.RedirectURL = o.RootURL + callback
	}

	routes["/oauth2/logout"] = o.logout

	return routes
}

// Storage requirements
func (o *OAuth2) Storage() authapi.StorageOptions {
	return authapi.StorageOptions{
		authapi.StoreEmail:          authapi.String,
		authapi.StoreOAuth2UID:      authapi.String,
		authapi.StoreOAuth2Provider: authapi.String,
		authapi.StoreOAuth2Token:    authapi.String,
		authapi.StoreOAuth2Refresh:  authapi.String,
		authapi.StoreOAuth2Expiry:   authapi.DateTime,
	}
}

func (o *OAuth2) oauthInit(ctx *authapi.Context, w http.ResponseWriter, r *http.Request) error {
	provider := strings.ToLower(filepath.Base(r.URL.Path))
	cfg, ok := o.OAuth2Providers[provider]
	if !ok {
		return fmt.Errorf("OAuth2 provider %q not found", provider)
	}

	random := make([]byte, 32)
	_, err := rand.Read(random)
	if err != nil {
		return err
	}

	state := base64.URLEncoding.EncodeToString(random)
	ctx.SessionStorer.Put(authapi.SessionOAuth2State, state)

	passAlongs := make(map[string]string)
	for k, vals := range r.URL.Query() {
		for _, val := range vals {
			passAlongs[k] = val
		}
	}

	if len(passAlongs) > 0 {
		str, err := json.Marshal(passAlongs)
		if err != nil {
			return err
		}
		ctx.SessionStorer.Put(authapi.SessionOAuth2Params, string(str))
	} else {
		ctx.SessionStorer.Del(authapi.SessionOAuth2Params)
	}

	url := cfg.OAuth2Config.AuthCodeURL(state)

	extraParams := cfg.AdditionalParams.Encode()
	if len(extraParams) > 0 {
		url = fmt.Sprintf("%s&%s", url, extraParams)
	}

	http.Redirect(w, r, url, http.StatusFound)
	return nil
}

// for testing
var exchanger = (*oauth2.Config).Exchange

func (o *OAuth2) oauthCallback(ctx *authapi.Context, w http.ResponseWriter, r *http.Request) error {
	provider := strings.ToLower(filepath.Base(r.URL.Path))

	sessState, err := ctx.SessionStorer.GetErr(authapi.SessionOAuth2State)
	ctx.SessionStorer.Del(authapi.SessionOAuth2State)
	if err != nil {
		return err
	}

	sessValues, ok := ctx.SessionStorer.Get(authapi.SessionOAuth2Params)
	// Don't delete this value from session immediately, callbacks use this too
	var values map[string]string
	if ok {
		if err := json.Unmarshal([]byte(sessValues), &values); err != nil {
			return err
		}
	}

	hasErr := r.FormValue("error")
	if len(hasErr) > 0 {
		return response.JSONResponse(ctx,w,r,true,fmt.Sprintf("%s login cancelled or failed.", strings.Title(provider)),nil)
	}

	cfg, ok := o.OAuth2Providers[provider]
	if !ok {
		return fmt.Errorf("OAuth2 provider %q not found", provider)
	}

	// Ensure request is genuine
	state := r.FormValue(authapi.FormValueOAuth2State)
	splState := strings.Split(state, ";")
	if len(splState) == 0 || splState[0] != sessState {
		return errOAuthStateValidation
	}

	// Get the code
	code := r.FormValue("code")
	token, err := exchanger(cfg.OAuth2Config, o.Config.ContextProvider(r), code)
	if err != nil {
		return fmt.Errorf("Could not validate oauth2 code: %v", err)
	}

	user, err := cfg.Callback(o.Config.ContextProvider(r), *cfg.OAuth2Config, token)
	if err != nil {
		return err
	}

	// OAuth2UID is required.
	uid, err := user.StringErr(authapi.StoreOAuth2UID)
	if err != nil {
		return err
	}

	user[authapi.StoreOAuth2UID] = uid
	user[authapi.StoreOAuth2Provider] = provider
	user[authapi.StoreOAuth2Expiry] = token.Expiry
	user[authapi.StoreOAuth2Token] = token.AccessToken
	if len(token.RefreshToken) != 0 {
		user[authapi.StoreOAuth2Refresh] = token.RefreshToken
	}

	if err = ctx.OAuth2Storer.PutOAuth(uid, provider, user); err != nil {
		return err
	}

	// Fully log user in
	ctx.SessionStorer.Put(authapi.SessionKey, fmt.Sprintf("%s;%s", uid, provider))
	ctx.SessionStorer.Del(authapi.SessionHalfAuthKey)

	if err = o.Callbacks.FireAfter(authapi.EventOAuth, ctx); err != nil {
		return nil
	}

	ctx.SessionStorer.Del(authapi.SessionOAuth2Params)

	sf := fmt.Sprintf("Logged in successfully with %s.", strings.Title(provider))
	return response.JSONResponse(ctx,w,r,false,sf,nil);
}

func (o *OAuth2) logout(ctx *authapi.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case "GET":
		ctx.SessionStorer.Del(authapi.SessionKey)
		ctx.CookieStorer.Del(authapi.CookieRemember)
		ctx.SessionStorer.Del(authapi.SessionLastAction)

		return response.JSONResponse(ctx,w,r,false,"Logged out successfully.",nil)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return nil
}
