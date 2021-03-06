// Package recover implements password reset via e-mail.
package recover

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/socodeit/authapi"
	"github.com/socodeit/authapi/internal/response"
	"golang.org/x/crypto/bcrypt"
)

// Storage constants
const (
	StoreRecoverToken       = "recover_token"
	StoreRecoverTokenExpiry = "recover_token_expiry"
)

const (
	formValueToken = "token"
)

const (
	methodGET  = "GET"
	methodPOST = "POST"

	tplLogin           = "login.html.tpl"
	tplRecover         = "recover.html.tpl"
	tplRecoverComplete = "recover_complete.html.tpl"
	tplInitHTMLEmail   = "recover_email.html.tpl"
	tplInitTextEmail   = "recover_email.txt.tpl"

	recoverInitiateSuccessFlash = "An email has been sent with further instructions on how to reset your password"
	recoverTokenExpiredFlash    = "Account recovery request has expired. Please try again."
	recoverFailedErrorFlash     = "Account recovery has failed. Please contact tech support."
	recoverUserNotFound			 = "User not found with this email id."
)

var errRecoveryTokenExpired = errors.New("recovery token expired")

// RecoverStorer must be implemented in order to satisfy the recover module's
// storage requirements.
type RecoverStorer interface {
	authapi.Storer
	// RecoverUser looks a user up by a recover token. See recover module for
	// attribute names. If the key is not found in the data store,
	// simply return nil, ErrUserNotFound.
	RecoverUser(recoverToken string) (interface{}, error)
}

func init() {
	m := &Recover{}
	authapi.RegisterModule("recover", m)
}

// Recover module
type Recover struct {
	*authapi.Authapi
	emailHTMLTemplates response.Templates
	emailTextTemplates response.Templates
}

// Initialize module
func (r *Recover) Initialize(ab *authapi.Authapi) (err error) {
	r.Authapi = ab

	if r.Storer != nil {
		if _, ok := r.Storer.(RecoverStorer); !ok {
			return errors.New("recover: RecoverStorer required for recover functionality")
		}
	} else if r.StoreMaker == nil {
		return errors.New("recover: Need a RecoverStorer")
	}

	if len(r.XSRFName) == 0 {
		return errors.New("auth: XSRFName must be set")
	}

	if r.XSRFMaker == nil {
		return errors.New("auth: XSRFMaker must be defined")
	}

	r.emailHTMLTemplates, err = response.LoadTemplates(r.Authapi, r.LayoutHTMLEmail, r.ViewsPath, tplInitHTMLEmail)
	if err != nil {
		return err
	}
	r.emailTextTemplates, err = response.LoadTemplates(r.Authapi, r.LayoutTextEmail, r.ViewsPath, tplInitTextEmail)
	if err != nil {
		return err
	}

	return nil
}

// Routes for module
func (r *Recover) Routes() authapi.RouteTable {
	return authapi.RouteTable{
		"/recover":          r.startHandlerFunc,
		"/recover/complete": r.completeHandlerFunc,
	}
}

// Storage requirements
func (r *Recover) Storage() authapi.StorageOptions {
	return authapi.StorageOptions{
		r.PrimaryID:             authapi.String,
		authapi.StoreEmail:     authapi.String,
		authapi.StorePassword:  authapi.String,
		StoreRecoverToken:       authapi.String,
		StoreRecoverTokenExpiry: authapi.String,
	}
}

func (rec *Recover) startHandlerFunc(ctx *authapi.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case methodGET:
		return response.JSONResponse(ctx,w,r,false,"This api is used to restore/recover account.",[]string{rec.PrimaryID,"confirm_"+rec.PrimaryID,"csrf_token"})
	case methodPOST:
		primaryID := r.FormValue(rec.PrimaryID)

		policies := authapi.FilterValidators(rec.Policies, rec.PrimaryID)
		if validationErrs := authapi.Validate(r, policies, rec.PrimaryID, authapi.ConfirmPrefix+rec.PrimaryID).Map(); len(validationErrs) > 0 {
			return response.JSONResponse(ctx,w,r,true,validationErrs,nil)
		}

		// redirect to login when user not found to prevent username sniffing
		if err := ctx.LoadUser(primaryID); err == authapi.ErrUserNotFound {
			return response.JSONResponse(ctx,w,r,true,recoverUserNotFound,nil)
		} else if err != nil {
			return err
		}

		email, err := ctx.User.StringErr(authapi.StoreEmail)
		if err != nil {
			return err
		}

		encodedToken, encodedChecksum, err := newToken()
		if err != nil {
			return err
		}

		ctx.User[StoreRecoverToken] = encodedChecksum
		ctx.User[StoreRecoverTokenExpiry] = time.Now().Add(rec.RecoverTokenDuration)

		if err := ctx.SaveUser(); err != nil {
			return err
		}

		goRecoverEmail(rec, ctx, email, encodedToken)
		return response.JSONResponse(ctx,w,r,false,recoverInitiateSuccessFlash,nil)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return nil
}

func newToken() (encodedToken, encodedChecksum string, err error) {
	token := make([]byte, 32)
	if _, err = rand.Read(token); err != nil {
		return "", "", err
	}
	sum := md5.Sum(token)

	return base64.URLEncoding.EncodeToString(token), base64.StdEncoding.EncodeToString(sum[:]), nil
}

var goRecoverEmail = func(r *Recover, ctx *authapi.Context, to, encodedToken string) {
	if ctx.MailMaker != nil {
		r.sendRecoverEmail(ctx, to, encodedToken)
	} else {
		go r.sendRecoverEmail(ctx, to, encodedToken)
	}
}

func (r *Recover) sendRecoverEmail(ctx *authapi.Context, to, encodedToken string) {
	p := path.Join(r.MountPath, "recover/complete")
	query := url.Values{formValueToken: []string{encodedToken}}
	url := fmt.Sprintf("%s%s?%s", r.SiteURL, p, query.Encode())

	email := authapi.Email{
		To:       []string{to},
		From:     r.EmailFrom,
		FromName: r.EmailFromName,
		Subject:  r.EmailSubjectPrefix + "Password Reset",
	}

	if err := response.Email(ctx.Mailer, email, r.emailHTMLTemplates, tplInitHTMLEmail, r.emailTextTemplates, tplInitTextEmail, url); err != nil {
		fmt.Fprintln(ctx.LogWriter, "recover: failed to send recover email:", err)
	}
}

func (r *Recover) completeHandlerFunc(ctx *authapi.Context, w http.ResponseWriter, req *http.Request) (err error) {
	switch req.Method {
	case methodGET:
		_, err = verifyToken(ctx, req)
		if err == errRecoveryTokenExpired {
			return response.JSONResponse(ctx,w,req,true,recoverTokenExpiredFlash,nil)
		} else if err != nil {
			return response.JSONResponse(ctx,w,req,true,err,[]string{"password","confirm_password","token","csrf_token"})
		}

		token := req.FormValue(formValueToken)
		return response.JSONResponse(ctx,w,req,false,"Token: "+token,nil)
	case methodPOST:
		token := req.FormValue(formValueToken)
		if len(token) == 0 {
			return authapi.ClientDataErr{Name: formValueToken}
		}

		password := req.FormValue(authapi.StorePassword)
		//confirmPassword, _ := ctx.FirstPostFormValue("confirmPassword")

		policies := authapi.FilterValidators(r.Policies, authapi.StorePassword)
		if validationErrs := authapi.Validate(req, policies, authapi.StorePassword, authapi.ConfirmPrefix+authapi.StorePassword).Map(); len(validationErrs) > 0 {
			return response.JSONResponse(ctx,w,req,true,validationErrs,nil)
		}

		if ctx.User, err = verifyToken(ctx, req); err != nil {
			return err
		}

		encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(password), r.BCryptCost)
		if err != nil {
			return err
		}

		ctx.User[authapi.StorePassword] = string(encryptedPassword)
		ctx.User[StoreRecoverToken] = ""
		var nullTime time.Time
		ctx.User[StoreRecoverTokenExpiry] = nullTime

		primaryID, err := ctx.User.StringErr(r.PrimaryID)
		if err != nil {
			return err
		}

		if err := ctx.SaveUser(); err != nil {
			return err
		}

		if err := r.Callbacks.FireAfter(authapi.EventPasswordReset, ctx); err != nil {
			return err
		}

		if r.Authapi.AllowLoginAfterResetPassword {
			ctx.SessionStorer.Put(authapi.SessionKey, primaryID)
		}
		return response.JSONResponse(ctx,w,req,false,"Password changed successfully.",nil)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return nil
}

// verifyToken expects a base64.URLEncoded token.
func verifyToken(ctx *authapi.Context, r *http.Request) (attrs authapi.Attributes, err error) {
	token := r.FormValue(formValueToken)
	if len(token) == 0 {
		return nil, authapi.ClientDataErr{Name: token}
	}

	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	sum := md5.Sum(decoded)
	storer := ctx.Storer.(RecoverStorer)

	userInter, err := storer.RecoverUser(base64.StdEncoding.EncodeToString(sum[:]))
	if err != nil {
		return nil, err
	}

	attrs = authapi.Unbind(userInter)

	expiry, ok := attrs.DateTime(StoreRecoverTokenExpiry)
	if !ok || time.Now().After(expiry) {
		return nil, errRecoveryTokenExpired
	}

	return attrs, nil
}
