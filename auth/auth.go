// Package auth implements password based user logins.
package auth

import (
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"
	"github.com/socodeit/authapi"
	"github.com/socodeit/authapi/internal/response"
)

const (
	methodGET  = "GET"
	methodPOST = "POST"

	tplLogin = "login.html.tpl"
)

func init() {
	authapi.RegisterModule("auth", &Auth{})
}

// Auth module
type Auth struct {
	*authapi.Authapi
}

// Initialize module
func (a *Auth) Initialize(ab *authapi.Authapi) (err error) {
	a.Authapi = ab

	if a.Storer == nil && a.StoreMaker == nil {
		return errors.New("auth: Need a Storer")
	}

	if len(a.XSRFName) == 0 {
		return errors.New("auth: XSRFName must be set")
	}

	if a.XSRFMaker == nil {
		return errors.New("auth: XSRFMaker must be defined")
	}

	return nil
}

// Routes for the module
func (a *Auth) Routes() authapi.RouteTable {
	return authapi.RouteTable{
		"/login":  a.loginHandlerFunc,
		"/logout": a.logoutHandlerFunc,
	}
}

// Storage requirements
func (a *Auth) Storage() authapi.StorageOptions {
	return authapi.StorageOptions{
		a.PrimaryID:            authapi.String,
		authapi.StorePassword: authapi.String,
	}
}

func (a *Auth) loginHandlerFunc(ctx *authapi.Context, w http.ResponseWriter, r *http.Request) error {
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
			if err := a.Callbacks.FireAfter(authapi.EventAuthFail, ctx); err != nil {
				fmt.Fprintf(ctx.LogWriter, "EventAuthFail callback error'd out: %v\n", err)
			}
			return response.JSONResponse(ctx,w,r,true,fmt.Sprintf("invalid %s and/or password", a.PrimaryID),nil)
		}

		interrupted, err := a.Callbacks.FireBefore(authapi.EventAuth, ctx)
		if err != nil {
			return err
		} else if interrupted != authapi.InterruptNone {
			switch interrupted {
			case authapi.InterruptAccountLocked:
				message = "Your account has been locked."
			case authapi.InterruptAccountNotConfirmed:
				message = "Your account has not been confirmed."
			}
			response.JSONResponse(ctx,w,r,true,message,nil)
		}

		ctx.SessionStorer.Put(authapi.SessionKey, key)
		ctx.SessionStorer.Del(authapi.SessionHalfAuthKey)
		ctx.Values = map[string]string{authapi.CookieRemember: r.FormValue(authapi.CookieRemember)}

		if err := a.Callbacks.FireAfter(authapi.EventAuth, ctx); err != nil {
			return err
		}
		response.JSONResponse(ctx,w,r,false,message,nil)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return nil
}

func validateCredentials(ctx *authapi.Context, key, password string) (bool, error) {
	if err := ctx.LoadUser(key); err == authapi.ErrUserNotFound {
		return false, nil
	} else if err != nil {
		return false, err
	}

	actualPassword, err := ctx.User.StringErr(authapi.StorePassword)
	if err != nil {
		return false, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(actualPassword), []byte(password)); err != nil {
		return false, nil
	}

	return true, nil
}

func (a *Auth) logoutHandlerFunc(ctx *authapi.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case methodGET:
		ctx.SessionStorer.Del(authapi.SessionKey)
		ctx.CookieStorer.Del(authapi.CookieRemember)
		ctx.SessionStorer.Del(authapi.SessionLastAction)
		return response.JSONResponse(ctx,w,r,false,"Logged out successfully.",nil)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return nil
}
