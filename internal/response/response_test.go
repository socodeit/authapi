package response

import (
	"html/template"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/socodeit/authapi"
	"github.com/socodeit/authapi/internal/mocks"
)

var testViewTemplate = template.Must(template.New("").Parse(`{{.external}} {{.fun}} {{.flash_success}} {{.flash_error}} {{.xsrfName}} {{.xsrfToken}}`))
var testEmailHTMLTemplate = template.Must(template.New("").Parse(`<h2>{{.}}</h2>`))
var testEmailPlainTemplate = template.Must(template.New("").Parse(`i am a {{.}}`))

func TestLoadTemplates(t *testing.T) {
	t.Parallel()

	file, err := ioutil.TempFile(os.TempDir(), "authapi")
	if err != nil {
		t.Error("Unexpected error:", err)
	}
	if _, err := file.Write([]byte("{{.Val}}")); err != nil {
		t.Error("Error writing to temp file", err)
	}

	layout, err := template.New("").Parse(`<strong>{{template "authapi" .}}</strong>`)
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	filename := filepath.Base(file.Name())

	tpls, err := LoadTemplates(authapi.New(), layout, filepath.Dir(file.Name()), filename)
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	if len(tpls) != 1 {
		t.Error("Expected 1 template:", len(tpls))
	}

	if _, ok := tpls[filename]; !ok {
		t.Error("Expected tpl with name:", filename)
	}
}

func TestTemplates_Render(t *testing.T) {
	t.Parallel()

	cookies := mocks.NewMockClientStorer()
	ab := authapi.New()
	ab.XSRFName = "do you think"
	ab.XSRFMaker = func(_ http.ResponseWriter, _ *http.Request) string {
		return "that's air you're breathing now?"
	}

	// Set up flashes
	cookies.Put(authapi.FlashSuccessKey, "no")
	cookies.Put(authapi.FlashErrorKey, "spoon")

	r, _ := http.NewRequest("GET", "http://localhost", nil)
	w := httptest.NewRecorder()
	ctx := ab.NewContext()
	ctx.SessionStorer = cookies

	if w.Body.String() != "there is no spoon do you think that's air you're breathing now?" {
		t.Error("Body was wrong:", w.Body.String())
	}
}

func Test_Email(t *testing.T) {
	t.Parallel()

	ab := authapi.New()
	mockMailer := &mocks.MockMailer{}
	ab.Mailer = mockMailer

	htmlTpls := Templates{"html": testEmailHTMLTemplate}
	textTpls := Templates{"plain": testEmailPlainTemplate}

	email := authapi.Email{
		To: []string{"a@b.c"},
	}

	err := Email(ab.Mailer, email, htmlTpls, "html", textTpls, "plain", "spoon")
	if err != nil {
		t.Error(err)
	}

	if len(mockMailer.Last.To) != 1 {
		t.Error("Expected 1 to addr")
	}
	if mockMailer.Last.To[0] != "a@b.c" {
		t.Error("Unexpected to addr @ 0:", mockMailer.Last.To[0])
	}

	if mockMailer.Last.HTMLBody != "<h2>spoon</h2>" {
		t.Error("Unexpected HTMLBody:", mockMailer.Last.HTMLBody)
	}

	if mockMailer.Last.TextBody != "i am a spoon" {
		t.Error("Unexpected TextBody:", mockMailer.Last.TextBody)
	}
}
