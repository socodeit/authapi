package remember

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/socodeit/authapi"
	"github.com/socodeit/authapi/internal/mocks"
)

func TestInitialize(t *testing.T) {
	t.Parallel()

	ab := authapi.New()
	r := &Remember{}
	err := r.Initialize(ab)
	if err == nil {
		t.Error("Expected error about token storers.")
	}

	ab.Storer = mocks.MockFailStorer{}
	err = r.Initialize(ab)
	if err == nil {
		t.Error("Expected error about token storers.")
	}

	ab.Storer = mocks.NewMockStorer()
	err = r.Initialize(ab)
	if err != nil {
		t.Error("Unexpected error:", err)
	}
}

func TestAfterAuth(t *testing.T) {
	t.Parallel()

	r := Remember{authapi.New()}
	storer := mocks.NewMockStorer()
	r.Storer = storer

	cookies := mocks.NewMockClientStorer()
	session := mocks.NewMockClientStorer()

	req, err := http.NewRequest("POST", "http://localhost", bytes.NewBufferString("rm=true"))
	if err != nil {
		t.Error("Unexpected Error:", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ctx := r.NewContext()
	ctx.SessionStorer = session
	ctx.CookieStorer = cookies
	ctx.User = authapi.Attributes{r.PrimaryID: "test@email.com"}

	ctx.Values = map[string]string{authapi.CookieRemember: "true"}

	if err := r.afterAuth(ctx); err != nil {
		t.Error(err)
	}

	if _, ok := cookies.Values[authapi.CookieRemember]; !ok {
		t.Error("Expected a cookie to have been set.")
	}
}

func TestAfterOAuth(t *testing.T) {
	t.Parallel()

	r := Remember{authapi.New()}
	storer := mocks.NewMockStorer()
	r.Storer = storer

	cookies := mocks.NewMockClientStorer()
	session := mocks.NewMockClientStorer(authapi.SessionOAuth2Params, `{"rm":"true"}`)

	ctx := r.NewContext()
	ctx.SessionStorer = session
	ctx.CookieStorer = cookies
	ctx.User = authapi.Attributes{
		authapi.StoreOAuth2UID:      "uid",
		authapi.StoreOAuth2Provider: "google",
	}

	if err := r.afterOAuth(ctx); err != nil {
		t.Error(err)
	}

	if _, ok := cookies.Values[authapi.CookieRemember]; !ok {
		t.Error("Expected a cookie to have been set.")
	}
}

func TestAfterPasswordReset(t *testing.T) {
	t.Parallel()

	r := Remember{authapi.New()}

	id := "test@email.com"

	storer := mocks.NewMockStorer()
	r.Storer = storer
	session := mocks.NewMockClientStorer()
	cookies := mocks.NewMockClientStorer()
	storer.Tokens[id] = []string{"one", "two"}
	cookies.Values[authapi.CookieRemember] = "token"

	ctx := r.NewContext()
	ctx.User = authapi.Attributes{r.PrimaryID: id}
	ctx.SessionStorer = session
	ctx.CookieStorer = cookies

	if err := r.afterPassword(ctx); err != nil {
		t.Error(err)
	}

	if _, ok := cookies.Values[authapi.CookieRemember]; ok {
		t.Error("Expected the remember cookie to be deleted.")
	}

	if len(storer.Tokens) != 0 {
		t.Error("Should have wiped out all tokens.")
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	r := &Remember{authapi.New()}
	storer := mocks.NewMockStorer()
	r.Storer = storer
	cookies := mocks.NewMockClientStorer()

	key := "tester"
	token, err := r.new(cookies, key)

	if err != nil {
		t.Error("Unexpected error:", err)
	}

	if len(token) == 0 {
		t.Error("Expected a token.")
	}

	if tok, ok := storer.Tokens[key]; !ok {
		t.Error("Expected it to store against the key:", key)
	} else if len(tok) != 1 || len(tok[0]) == 0 {
		t.Error("Expected a token to be saved.")
	}

	if token != cookies.Values[authapi.CookieRemember] {
		t.Error("Expected a cookie set with the token.")
	}
}

func TestAuth(t *testing.T) {
	t.Parallel()

	r := &Remember{authapi.New()}
	storer := mocks.NewMockStorer()
	r.Storer = storer

	cookies := mocks.NewMockClientStorer()
	session := mocks.NewMockClientStorer()
	ctx := r.NewContext()
	ctx.CookieStorer = cookies
	ctx.SessionStorer = session

	key := "tester"
	_, err := r.new(cookies, key)
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	cookie, _ := cookies.Get(authapi.CookieRemember)

	interrupt, err := r.auth(ctx)
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	if session.Values[authapi.SessionHalfAuthKey] != "true" {
		t.Error("The user should have been half-authed.")
	}

	if session.Values[authapi.SessionKey] != key {
		t.Error("The user should have been logged in.")
	}

	if chocolateChip, _ := cookies.Get(authapi.CookieRemember); chocolateChip == cookie {
		t.Error("Expected cookie to be different")
	}

	if authapi.InterruptNone != interrupt {
		t.Error("Keys should have matched:", interrupt)
	}
}
