package renewal

import (
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
)

// reminderTemplateData is what an operator's subject/body template (see
// ReminderSettings) can reference. Keep this in sync with the field names
// docs/README mentions — it's the whole point of making the template
// editable.
type reminderTemplateData struct {
	CommonName    string
	Domains       []string
	OwningTeam    string
	CAProvider    string
	DaysRemaining int
	NotAfter      string
}

func renderReminder(subjectTpl, bodyTpl string, cert certificate.Certificate, thresholdDays int) (subject, body string, err error) {
	data := reminderTemplateData{
		CommonName:    cert.CommonName,
		Domains:       cert.SANs,
		OwningTeam:    cert.OwningTeam,
		CAProvider:    cert.CAProvider,
		DaysRemaining: thresholdDays,
		NotAfter:      cert.NotAfter.Format("2006-01-02"),
	}

	subject, err = renderTemplate("subject", subjectTpl, data)
	if err != nil {
		return "", "", fmt.Errorf("render subject template: %w", err)
	}
	body, err = renderTemplate("body", bodyTpl, data)
	if err != nil {
		return "", "", fmt.Errorf("render body template: %w", err)
	}
	return subject, body, nil
}

// ValidateTemplates renders subjectTpl/bodyTpl against a placeholder
// certificate so a caller (the notification-settings API) can reject a
// malformed template at save time instead of failing silently on every
// tick afterward.
func ValidateTemplates(subjectTpl, bodyTpl string) error {
	placeholder := certificate.Certificate{
		CommonName: "example.test", SANs: []string{"example.test"},
		OwningTeam: "example-team", CAProvider: "letsencrypt", NotAfter: time.Now(),
	}
	_, _, err := renderReminder(subjectTpl, bodyTpl, placeholder, 30)
	return err
}

func renderTemplate(name, tpl string, data reminderTemplateData) (string, error) {
	t, err := template.New(name).Parse(tpl)
	if err != nil {
		return "", err
	}
	var buf strings.Builder
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
