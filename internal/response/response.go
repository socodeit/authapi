// Package response is responsible for loading and rendering authboss templates.
package response

//go:generate go-bindata -pkg=response -prefix=templates templates

import (
	"bytes"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/socodeit/authboss"
	"encoding/json"
	"errors"
)

var (
	// ErrTemplateNotFound should be returned from Get when the view is not found
	ErrTemplateNotFound = errors.New("Template not found")
)

type GETJSONResp struct {
	Error bool `json:"error"`
	Message interface{} `json:"message"`
	Params []string `json:"params"`
}

type POSTJSONResp struct{
	Error bool `json:"error"`
	Message interface{} `json:"message"`
}
// Templates is a map depicting the forms a template needs wrapped within the specified layout
type Templates map[string]*template.Template

// LoadTemplates parses all specified files located in fpath. Each template is wrapped
// in a unique clone of layout.  All templates are expecting {{authboss}} handlebars
// for parsing. It will check the override directory specified in the config, replacing any
// templates as necessary.
func LoadTemplates(ab *authboss.Authboss, layout *template.Template, fpath string, files ...string) (Templates, error) {
	m := make(Templates)

	funcMap := template.FuncMap{
		"title": strings.Title,
		"mountpathed": func(location string) string {
			if ab.MountPath == "/" {
				return location
			}
			return path.Join(ab.MountPath, location)
		},
	}

	for _, file := range files {
		b, err := ioutil.ReadFile(filepath.Join(fpath, file))
		if exists := !os.IsNotExist(err); err != nil && exists {
			return nil, err
		} else if !exists {
			b, err = Asset(file)
			if err != nil {
				return nil, err
			}
		}

		clone, err := layout.Clone()
		if err != nil {
			return nil, err
		}

		_, err = clone.New("authboss").Funcs(funcMap).Parse(string(b))
		if err != nil {
			return nil, err
		}

		m[file] = clone
	}

	return m, nil
}

func JSONResponse(ctx *authboss.Context, w http.ResponseWriter, r *http.Request, error bool,message interface{}, params []string) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if params==nil {
		// POST Response
		err := json.NewEncoder(w).Encode(POSTJSONResp{Error:error,Message:message})
		if err!=nil{
			return err
		}
	} else {
		err := json.NewEncoder(w).Encode(GETJSONResp{Error:error,Message:message,Params:params})
		if err!=nil{
			return err
		}
	}
	return nil;
}

// RenderEmail renders the html and plaintext views for an email and sends it
func Email(mailer authboss.Mailer, email authboss.Email, htmlTpls Templates, nameHTML string, textTpls Templates, namePlain string, data interface{}) error {
	tplHTML, ok := htmlTpls[nameHTML]
	if !ok {
		return authboss.RenderErr{TemplateName: tplHTML.Name(), Data: data, Err: ErrTemplateNotFound}
	}

	tplPlain, ok := textTpls[namePlain]
	if !ok {
		return authboss.RenderErr{TemplateName: tplPlain.Name(), Data: data, Err: ErrTemplateNotFound}
	}

	htmlBuffer := &bytes.Buffer{}
	if err := tplHTML.ExecuteTemplate(htmlBuffer, tplHTML.Name(), data); err != nil {
		return authboss.RenderErr{TemplateName: tplHTML.Name(), Data: data, Err: err}
	}
	email.HTMLBody = htmlBuffer.String()

	plainBuffer := &bytes.Buffer{}
	if err := tplPlain.ExecuteTemplate(plainBuffer, tplPlain.Name(), data); err != nil {
		return authboss.RenderErr{TemplateName: tplPlain.Name(), Data: data, Err: err}
	}
	email.TextBody = plainBuffer.String()

	if err := mailer.Send(email); err != nil {
		return err
	}

	return nil
}
