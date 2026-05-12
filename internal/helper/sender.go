package helper

import (
	"fmt"
	"os"

	"github.com/resend/resend-go/v3"
)

func SendEmail(to string, subject string, html string) error {
	apiKey := os.Getenv("RESEND_KEY")
	if apiKey == "" {
		return fmt.Errorf("RESEND_KEY is not set")
	}

	client := resend.NewClient(apiKey)

	params := &resend.SendEmailRequest{
		From:    "onboarding@resend.dev",
		To:      []string{to},
		Subject: subject,
		Html:    html,
	}

	sent, err := client.Emails.Send(params)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	_ = sent.Id
	return nil
}

func SendResetToken(to string, subject string, html string) error {
	apiKey := os.Getenv("RESEND_KEY")
	if apiKey == "" {
		return fmt.Errorf("RESEND_KEY is not set")
	}

	client := resend.NewClient(apiKey)

	params := &resend.SendEmailRequest{
		From:    "onboarding@resend.dev",
		To:      []string{to},
		Subject: subject,
		Html:    html,
	}

	sent, err := client.Emails.Send(params)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	_ = sent.Id
	return nil
}
