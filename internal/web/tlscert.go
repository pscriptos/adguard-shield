package web

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"
)

const certCheckEvery = time.Minute

// certReloader liefert das TLS-Zertifikat und lädt es neu, sobald sich
// Zertifikat- oder Schlüsseldatei ändern (z.B. nach einer Let's-Encrypt-
// Erneuerung). Die Dateien werden höchstens alle certCheckEvery geprüft.
type certReloader struct {
	certFile, keyFile string
	log               Logger
	now               func() time.Time

	mu        sync.Mutex
	cert      *tls.Certificate
	stamp     string
	checkedAt time.Time
}

func newCertReloader(certFile, keyFile string, log Logger) (*certReloader, error) {
	c := &certReloader{certFile: certFile, keyFile: keyFile, log: log, now: time.Now}
	stamp, err := c.fileStamp()
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	c.cert, c.stamp, c.checkedAt = &cert, stamp, c.now()
	return c, nil
}

func (c *certReloader) fileStamp() (string, error) {
	var stamp string
	for _, f := range []string{c.certFile, c.keyFile} {
		fi, err := os.Stat(f)
		if err != nil {
			return "", err
		}
		stamp += fmt.Sprintf("%d/%d;", fi.ModTime().UnixNano(), fi.Size())
	}
	return stamp, nil
}

func (c *certReloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if now.Sub(c.checkedAt) < certCheckEvery {
		return c.cert, nil
	}
	c.checkedAt = now
	stamp, err := c.fileStamp()
	if err != nil {
		c.log.Warnf("Web-Statusseite: TLS-Zertifikat nicht prüfbar, nutze bisheriges: %v", err)
		return c.cert, nil
	}
	if stamp == c.stamp {
		return c.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		c.log.Warnf("Web-Statusseite: TLS-Zertifikat nicht neu geladen, nutze bisheriges: %v", err)
		return c.cert, nil
	}
	c.cert, c.stamp = &cert, stamp
	c.log.Infof("Web-Statusseite: TLS-Zertifikat neu geladen")
	return c.cert, nil
}
