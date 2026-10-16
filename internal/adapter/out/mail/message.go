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
	subject    = "Código de verificación de tu correo"
	senderName = "Cinesync Platform"
)

var errHeaderInjection = errors.New("an address contains a line break")

// buildMessage writes the plain-text UTF-8 message in Spanish that carries the code. The lifetime shown
// is the time left until expiresAt. An address with a line break is rejected so it cannot add headers.
func buildMessage(from, to, code string, expiresAt, now time.Time, messageID string) ([]byte, error) {
	if strings.ContainsAny(from+to, "\r\n") {
		return nil, errHeaderInjection
	}
	minutes := max(int(math.Round(expiresAt.Sub(now).Minutes())), 1)
	unit := "minutos"
	if minutes == 1 {
		unit = "minuto"
	}
	var message bytes.Buffer
	for _, header := range [][2]string{
		{"From", (&mail.Address{Name: senderName, Address: from}).String()},
		{"To", (&mail.Address{Address: to}).String()},
		{"Subject", mime.QEncoding.Encode("UTF-8", subject)},
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
	_, err := fmt.Fprintf(body, "Hola,\r\n\r\nTu código de verificación es: %s\r\n\r\nEs válido durante %d %s.\r\n\r\n"+
		"Si no lo solicitaste, puedes ignorar este mensaje.\r\n", code, minutes, unit)
	if err != nil {
		return nil, err
	}
	return message.Bytes(), body.Close()
}
