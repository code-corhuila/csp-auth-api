package mail

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"time"
)

const (
	subject            = "Código de verificación de tu correo"
	passwordResetTopic = "Restablece tu contraseña"
	senderName         = "Cinesync Platform"
)

var errHeaderInjection = errors.New("an address contains a line break")

// buildMessage writes the plain-text UTF-8 message in Spanish that carries the code. The lifetime shown
// is the time left until expiresAt. An address with a line break is rejected so it cannot add headers.
func buildMessage(from, to, code string, expiresAt, now time.Time, messageID string) ([]byte, error) {
	minutes, unit := lifetime(expiresAt, now)
	return assemble(from, to, subject, now, messageID, fmt.Sprintf(
		"Hola,\r\n\r\nTu código de verificación es: %s\r\n\r\nEs válido durante %d %s.\r\n\r\n"+
			"Si no lo solicitaste, puedes ignorar este mensaje.\r\n", code, minutes, unit))
}

// buildResetMessage writes the plain-text UTF-8 message in Spanish that carries the link to choose a new password
// (ADR-050), with the same rules as buildMessage.
func buildResetMessage(from, to, link string, expiresAt, now time.Time, messageID string) ([]byte, error) {
	minutes, unit := lifetime(expiresAt, now)
	return assemble(from, to, passwordResetTopic, now, messageID, fmt.Sprintf(
		"Hola,\r\n\r\nRecibimos una solicitud para restablecer tu contraseña. Abre este enlace para elegir una nueva:\r\n\r\n%s\r\n\r\n"+
			"El enlace es válido durante %d %s y puede usarse una sola vez.\r\n\r\n"+
			"Si no lo solicitaste, puedes ignorar este mensaje.\r\n", link, minutes, unit))
}

// lifetime is the whole minutes left until expiresAt, never under one, with the Spanish word for them.
func lifetime(expiresAt, now time.Time) (minutes int, unit string) {
	minutes = max(int(math.Round(expiresAt.Sub(now).Minutes())), 1)
	if minutes == 1 {
		return minutes, "minuto"
	}
	return minutes, "minutos"
}

func assemble(from, to, title string, now time.Time, messageID, text string) ([]byte, error) {
	if strings.ContainsAny(from+to, "\r\n") {
		return nil, errHeaderInjection
	}
	var message bytes.Buffer
	for _, header := range [][2]string{
		{"From", (&mail.Address{Name: senderName, Address: from}).String()},
		{"To", (&mail.Address{Address: to}).String()},
		{"Subject", mime.QEncoding.Encode("UTF-8", title)},
		{"Date", now.Format(time.RFC1123Z)},
		{"Message-ID", "<" + messageID + "@" + from[strings.LastIndex(from, "@")+1:] + ">"},
		{"MIME-Version", "1.0"},
		{"Content-Type", "text/plain; charset=UTF-8"},
		{"Content-Transfer-Encoding", "quoted-printable"},
	} {
		fmt.Fprintf(&message, "%s: %s\r\n", header[0], header[1])
	}
	message.WriteString("\r\n")
	body := quotedprintable.NewWriter(&message)
	if _, err := body.Write([]byte(text)); err != nil {
		return nil, err
	}
	return message.Bytes(), body.Close()
}
