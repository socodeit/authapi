// Package confirm implements confirmation of user registration via e-mail
package confirm

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/socodeit/authapi"
	"github.com/socodeit/authapi/internal/response"
)

// Storer and FormValue constants
const (
	StoreConfirmToken = "confirm_token"
	StoreConfirmed    = "confirmed"

	FormValueConfirm = "cnf"

	tplConfirmHTML = "confirm_email.html.tpl"
	tplConfirmText = "confirm_email.txt.tpl"
)

var (
	errUserMissing = errors.New("confirm: After registration user must be loaded")
)

// ConfirmStorer must be implemented in order to satisfy the confirm module's
// storage requirements.
type ConfirmStorer interface {
	authapi.Storer
	// ConfirmUser looks up a user by a confirm token. See confirm module for
	// attribute names. If the token is not found in the data store,
	// simply return nil, ErrUserNotFound.
	ConfirmUser(confirmToken string) (interface{}, error)
}

func init() {
	authapi.RegisterModule("confirm", &Confirm{})
}

// Confirm module
type Confirm struct {
	*authapi.Authapi
	emailHTMLTemplates response.Templates
	emailTextTemplates response.Templates
}

// Initialize the module
func (c *Confirm) Initialize(ab *authapi.Authapi) (err error) {
	c.Authapi = ab

	var ok bool
	storer, ok := c.Storer.(ConfirmStorer)
	if c.StoreMaker == nil && (storer == nil || !ok) {
		return errors.New("confirm: Need a ConfirmStorer")
	}

	c.emailHTMLTemplates, err = response.LoadTemplates(ab, c.LayoutHTMLEmail, c.ViewsPath, tplConfirmHTML)
	if err != nil {
		return err
	}
	c.emailTextTemplates, err = response.LoadTemplates(ab, c.LayoutTextEmail, c.ViewsPath, tplConfirmText)
	if err != nil {
		return err
	}

	c.Callbacks.After(authapi.EventGetUser, func(ctx *authapi.Context) error {
		_, err := c.beforeGet(ctx)
		return err
	})
	c.Callbacks.Before(authapi.EventAuth, c.beforeGet)
	c.Callbacks.After(authapi.EventRegister, c.afterRegister)

	return nil
}

// Routes for the module
func (c *Confirm) Routes() authapi.RouteTable {
	return authapi.RouteTable{
		"/confirm": c.confirmHandler,
	}
}

// Storage requirements
func (c *Confirm) Storage() authapi.StorageOptions {
	return authapi.StorageOptions{
		c.PrimaryID:         authapi.String,
		authapi.StoreEmail: authapi.String,
		StoreConfirmToken:   authapi.String,
		StoreConfirmed:      authapi.Bool,
	}
}

func (c *Confirm) beforeGet(ctx *authapi.Context) (authapi.Interrupt, error) {
	if confirmed, err := ctx.User.BoolErr(StoreConfirmed); err != nil {
		return authapi.InterruptNone, err
	} else if !confirmed {
		return authapi.InterruptAccountNotConfirmed, nil
	}

	return authapi.InterruptNone, nil
}

// AfterRegister ensures the account is not activated.
func (c *Confirm) afterRegister(ctx *authapi.Context) error {
	if ctx.User == nil {
		return errUserMissing
	}

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	sum := md5.Sum(token)

	ctx.User[StoreConfirmToken] = base64.StdEncoding.EncodeToString(sum[:])

	if err := ctx.SaveUser(); err != nil {
		return err
	}

	email, err := ctx.User.StringErr(authapi.StoreEmail)
	if err != nil {
		return err
	}

	goConfirmEmail(c, ctx, email, base64.URLEncoding.EncodeToString(token))

	return nil
}

var goConfirmEmail = func(c *Confirm, ctx *authapi.Context, to, token string) {
	if ctx.MailMaker != nil {
		c.confirmEmail(ctx, to, token)
	} else {
		go c.confirmEmail(ctx, to, token)
	}
}

// confirmEmail sends a confirmation e-mail.
func (c *Confirm) confirmEmail(ctx *authapi.Context, to, token string) {
	p := path.Join(c.MountPath, "confirm")
	url := fmt.Sprintf("%s%s?%s=%s", c.SiteURL, p, url.QueryEscape(FormValueConfirm), url.QueryEscape(token))

	email := authapi.Email{
		To:       []string{to},
		From:     c.EmailFrom,
		FromName: c.EmailFromName,
		Subject:  c.EmailSubjectPrefix + "Confirm New Account",
	}

	err := response.Email(ctx.Mailer, email, c.emailHTMLTemplates, tplConfirmHTML, c.emailTextTemplates, tplConfirmText, url)
	if err != nil {
		fmt.Fprintf(ctx.LogWriter, "confirm: Failed to send e-mail: %v", err)
	}
}

func (c *Confirm) confirmHandler(ctx *authapi.Context, w http.ResponseWriter, r *http.Request) error {
	token := r.FormValue(FormValueConfirm)
	if len(token) == 0 {
		return authapi.ClientDataErr{Name: FormValueConfirm}
	}

	toHash, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return authapi.ErrAndRedirect{
			Location: "/", Err: fmt.Errorf("confirm: token failed to decode %q => %v\n", token, err),
		}
	}

	sum := md5.Sum(toHash)

	dbTok := base64.StdEncoding.EncodeToString(sum[:])
	user, err := ctx.Storer.(ConfirmStorer).ConfirmUser(dbTok)
	if err == authapi.ErrUserNotFound {
		return authapi.ErrAndRedirect{Location: "/", Err: errors.New("confirm: token not found")}
	} else if err != nil {
		return err
	}

	ctx.User = authapi.Unbind(user)

	ctx.User[StoreConfirmToken] = ""
	ctx.User[StoreConfirmed] = true

	if err := ctx.SaveUser(); err != nil {
		return err
	}
	if c.Authapi.AllowInsecureLoginAfterConfirm {
		key, err := ctx.User.StringErr(c.PrimaryID)
		if err != nil {
			return err
		}
		ctx.SessionStorer.Put(authapi.SessionKey, key)
	}
	return response.JSONResponse(ctx,w,r,false,"Account confirmed.",nil)
}
