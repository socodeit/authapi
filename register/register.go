// Package register allows for user registration.
package register

import (
	"errors"
	"net/http"

	"golang.org/x/crypto/bcrypt"
	"github.com/socodeit/authapi"
	"github.com/socodeit/authapi/internal/response"
)

const (
	tplRegister = "register.html.tpl"
)

// RegisterStorer must be implemented in order to satisfy the register module's
// storage requirments.
type RegisterStorer interface {
	authapi.Storer
	// Create is the same as put, except it refers to a non-existent key.  If the key is
	// found simply return Authapi.ErrUserFound
	Create(key string, attr authapi.Attributes) error
}

func init() {
	authapi.RegisterModule("register", &Register{})
}

// Register module.
type Register struct {
	*authapi.Authapi
}

// Initialize the module.
func (r *Register) Initialize(ab *authapi.Authapi) (err error) {
	r.Authapi = ab

	if r.Storer != nil {
		if _, ok := r.Storer.(RegisterStorer); !ok {
			return errors.New("register: RegisterStorer required for register functionality")
		}
	} else if r.StoreMaker == nil {
		return errors.New("register: Need a RegisterStorer")
	}

	return nil
}

// Routes creates the routing table.
func (r *Register) Routes() authapi.RouteTable {
	return authapi.RouteTable{
		"/register": r.registerHandler,
	}
}

// Storage returns storage requirements.
func (r *Register) Storage() authapi.StorageOptions {
	return authapi.StorageOptions{
		r.PrimaryID:            authapi.String,
		authapi.StorePassword: authapi.String,
	}
}

func (reg *Register) registerHandler(ctx *authapi.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case "GET":
		return response.JSONResponse(ctx,w,r,false,"This api ised for user registration.",[]string{"<user-defined>","email","password","confirm_password","csrf_token"})
	case "POST":
		return reg.registerPostHandler(ctx, w, r)
	}
	return nil
}

func (reg *Register) registerPostHandler(ctx *authapi.Context, w http.ResponseWriter, r *http.Request) error {
	key := r.FormValue(reg.PrimaryID)
	password := r.FormValue(authapi.StorePassword)

	validationErrs := authapi.Validate(r, reg.Policies, reg.ConfirmFields...)

	if user, err := ctx.Storer.Get(key); err != nil && err != authapi.ErrUserNotFound {
		return err
	} else if user != nil {
		validationErrs = append(validationErrs, authapi.FieldError{Name: reg.PrimaryID, Err: errors.New("Already in use")})
	}

	if len(validationErrs) != 0 {
		return response.JSONResponse(ctx,w,r,true,validationErrs.Map(),nil)
	}

	attr, err := authapi.AttributesFromRequest(r) // Attributes from overriden forms
	if err != nil {
		return err
	}

	pass, err := bcrypt.GenerateFromPassword([]byte(password), reg.BCryptCost)
	if err != nil {
		return err
	}

	attr[reg.PrimaryID] = key
	attr[authapi.StorePassword] = string(pass)
	ctx.User = attr

	if err := ctx.Storer.(RegisterStorer).Create(key, attr); err == authapi.ErrUserFound {
		return response.JSONResponse(ctx,w,r,true,map[string][]string{reg.PrimaryID: []string{"Already in use"}},nil)
	} else if err != nil {
		return err
	}

	if err := reg.Callbacks.FireAfter(authapi.EventRegister, ctx); err != nil {
		return err
	}

	if reg.IsLoaded("confirm") {
		return response.JSONResponse(ctx,w,r,false,"Account successfully created, please verify your e-mail address.",nil)
	}

	ctx.SessionStorer.Put(authapi.SessionKey, key)
	return response.JSONResponse(ctx,w,r,false,"Account successfully created, you are now logged in.",nil)
}
