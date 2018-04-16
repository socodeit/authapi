// Package auth implements password based user logins.
package auth

import (
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"
	"github.com/socodeit/authboss"
	"github.com/socodeit/authboss/internal/response"
)

const (
	methodGET  = "GET"
	methodPOST = "POST"

	tplLogin = "login.html.tpl"
)

func init() {
	authboss.RegisterModule("auth", &Auth{})
}

// Auth module
type Auth struct {
	*authboss.Authboss
	templates response.Templates
}

// Initialize module
func (a *Auth) Initialize(ab *authboss.Authboss) (err error) {
	a.Authboss = ab

	if a.Storer == nil && a.StoreMaker == nil {
		return errors.New("auth: Need a Storer")
	}

	if len(a.XSRFName) == 0 {
		return errors.New("auth: XSRFName must be set")
	}

	if a.XSRFMaker == nil {
		return errors.New("auth: XSRFMaker must be defined")
	}

	a.templates, err = response.LoadTemplates(a.Authboss, a.Layout, a.ViewsPath, tplLogin)
	if err != nil {
		return err
	}

	return nil
}

// Routes for the module
func (a *Auth) Routes() authboss.RouteTable {
	return authboss.RouteTable{
		"/login":  a.loginHandlerFunc,
		"/logout": a.logoutHandlerFunc,
	}
}

// Storage requirements
func (a *Auth) Storage() authboss.StorageOptions {
	return authboss.StorageOptions{
		a.PrimaryID:            authboss.String,
		authboss.StorePassword: authboss.String,
	}
}

func (a *Auth) loginHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case methodGET:
		return response.JSONResponse(ctx,w,r,false,"This api is used for logging in.",[]string{"email","password","csrf_token"})
	case methodPOST:
		key := r.FormValue(a.PrimaryID)
		password := r.FormValue("password")

		message := "Login Successful."
		if valid, err := validateCredentials(ctx, key, password); err != nil {
			message = "Internal server error"
			fmt.Fprintf(ctx.LogWriter, "auth: validate credentials failed: %v\n", err)
			return response.JSONResponse(ctx,w,r,true,message,nil)
		} else if !valid {
			if err := a.Callbacks.FireAfter(authboss.EventAuthFail, ctx); err != nil {
				fmt.Fprintf(ctx.LogWriter, "EventAuthFail callback error'd out: %v\n", err)
			}
			return response.JSONResponse(ctx,w,r,true,fmt.Sprintf("invalid %s and/or password", a.PrimaryID),nil)
		}

		interrupted, err := a.Callbacks.FireBefore(authboss.EventAuth, ctx)
		if err != nil {
			return err
		} else if interrupted != authboss.InterruptNone {
			switch interrupted {
			case authboss.InterruptAccountLocked:
				message = "Your account has been locked."
			case authboss.InterruptAccountNotConfirmed:
				message = "Your account has not been confirmed."
			}
			response.JSONResponse(ctx,w,r,true,message,nil)
		}

		ctx.SessionStorer.Put(authboss.SessionKey, key)
		ctx.SessionStorer.Del(authboss.SessionHalfAuthKey)
		ctx.Values = map[string]string{authboss.CookieRemember: r.FormValue(authboss.CookieRemember)}

		if err := a.Callbacks.FireAfter(authboss.EventAuth, ctx); err != nil {
			return err
		}
		response.JSONResponse(ctx,w,r,false,message,nil)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return nil
}

func validateCredentials(ctx *authboss.Context, key, password string) (bool, error) {
	if err := ctx.LoadUser(key); err == authboss.ErrUserNotFound {
		return false, nil
	} else if err != nil {
		return false, err
	}

	actualPassword, err := ctx.User.StringErr(authboss.StorePassword)
	if err != nil {
		return false, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(actualPassword), []byte(password)); err != nil {
		return false, nil
	}

	return true, nil
}

func (a *Auth) logoutHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case methodGET:
		ctx.SessionStorer.Del(authboss.SessionKey)
		ctx.CookieStorer.Del(authboss.CookieRemember)
		ctx.SessionStorer.Del(authboss.SessionLastAction)
		return response.JSONResponse(ctx,w,r,false,"Logged out successfully.",nil)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return nil
}
