package register

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/socodeit/authapi"
	"github.com/socodeit/authapi/internal/mocks"
)

func setup() *Register {
	ab := authapi.New()
	ab.XSRFName = "xsrf"
	ab.XSRFMaker = func(_ http.ResponseWriter, _ *http.Request) string {
		return "xsrfvalue"
	}
	ab.ConfirmFields = []string{"password", "confirm_password"}
	ab.Storer = mocks.NewMockStorer()

	reg := Register{}
	if err := reg.Initialize(ab); err != nil {
		panic(err)
	}

	return &reg
}

func TestRegister(t *testing.T) {
	ab := authapi.New()
	ab.Storer = mocks.NewMockStorer()
	r := Register{}
	if err := r.Initialize(ab); err != nil {
		t.Error(err)
	}

	if r.Routes()["/register"] == nil {
		t.Error("Expected a register handler at /register.")
	}

	sto := r.Storage()
	if sto[r.PrimaryID] != authapi.String {
		t.Error("Wanted primary ID to be a string.")
	}
	if sto[authapi.StorePassword] != authapi.String {
		t.Error("Wanted password to be a string.")
	}
}

func TestRegisterGet(t *testing.T) {
	reg := setup()

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/register", nil)
	ctx := reg.NewContext()
	ctx.SessionStorer = mocks.NewMockClientStorer()

	if err := reg.registerHandler(ctx, w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusOK {
		t.Error("It should have written a 200:", w.Code)
	}

	if w.Body.Len() == 0 {
		t.Error("It should have wrote a response.")
	}

	if str := w.Body.String(); !strings.Contains(str, "<form") {
		t.Error("It should have rendered a nice form:", str)
	} else if !strings.Contains(str, `name="`+reg.PrimaryID) {
		t.Error("Form should contain the primary ID:", str)
	}
}

func TestRegisterPostValidationErrs(t *testing.T) {
	reg := setup()

	w := httptest.NewRecorder()
	vals := url.Values{}

	email := "email@address.com"
	vals.Set(reg.PrimaryID, email)
	vals.Set(authapi.StorePassword, "pass")
	vals.Set(authapi.ConfirmPrefix+authapi.StorePassword, "pass2")

	r, _ := http.NewRequest("POST", "/register", bytes.NewBufferString(vals.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := reg.NewContext()
	ctx.SessionStorer = mocks.NewMockClientStorer()

	if err := reg.registerHandler(ctx, w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusOK {
		t.Error("It should have written a 200:", w.Code)
	}

	if w.Body.Len() == 0 {
		t.Error("It should have wrote a response.")
	}

	if str := w.Body.String(); !strings.Contains(str, "Does not match password") {
		t.Error("Confirm password should have an error:", str)
	}

	if _, err := reg.Storer.Get(email); err != authapi.ErrUserNotFound {
		t.Error("The user should not have been saved.")
	}
}

func TestRegisterPostSuccess(t *testing.T) {
	reg := setup()
	reg.Policies = nil

	w := httptest.NewRecorder()
	vals := url.Values{}

	email := "email@address.com"
	vals.Set(reg.PrimaryID, email)
	vals.Set(authapi.StorePassword, "pass")
	vals.Set(authapi.ConfirmPrefix+authapi.StorePassword, "pass")

	r, _ := http.NewRequest("POST", "/register", bytes.NewBufferString(vals.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := reg.NewContext()
	ctx.SessionStorer = mocks.NewMockClientStorer()

	if err := reg.registerHandler(ctx, w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusFound {
		t.Error("It should have written a redirect:", w.Code)
	}

	user, err := reg.Storer.Get(email)
	if err == authapi.ErrUserNotFound {
		t.Error("The user have been saved.")
	}

	attrs := authapi.Unbind(user)
	if e, err := attrs.StringErr(reg.PrimaryID); err != nil {
		t.Error(err)
	} else if e != email {
		t.Errorf("Email was not set properly, want: %s, got: %s", email, e)
	}

	if p, err := attrs.StringErr(authapi.StorePassword); err != nil {
		t.Error(err)
	} else if p == "pass" {
		t.Error("Password was not hashed.")
	}
}
