package passive

import (
	"context"
	"crypto/tls"
	"time"
)

func (s *PassiveScanner) sslCertAnalysis(ctx context.Context) error {
	conn, err := tls.Dial("tcp", s.Target+":443", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	
	state := conn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		s.mu.Lock()
		s.Results.SSLCertificates = append(s.Results.SSLCertificates, Certificate{
			Subject:       cert.Subject.String(),
			Issuer:        cert.Issuer.String(),
			ValidFrom:     cert.NotBefore,
			ValidTo:       cert.NotAfter,
			SANs:          cert.DNSNames,
			KeyAlgorithm:  cert.PublicKeyAlgorithm.String(),
			SignAlgorithm: cert.SignatureAlgorithm.String(),
		})
		s.mu.Unlock()
	}
	
	return nil
}

func (s *PassiveScanner) certTransparencyLogs(ctx context.Context) error {
	// Already handled in subdominEnumCrtSh
	return nil
}

func (s *PassiveScanner) certChainValidation(ctx context.Context) error {
	// Certificate chain validation
	return nil
}

func (s *PassiveScanner) certExpiryTracking(ctx context.Context) error {
	// Track certificate expiry dates
	s.mu.Lock()
	defer s.mu.Unlock()
	
	for _, cert := range s.Results.SSLCertificates {
		daysLeft := int(time.Until(cert.ValidTo).Hours() / 24)
		if daysLeft < 30 {
			s.Results.RiskIndicators = append(s.Results.RiskIndicators, RiskIndicator{
				Category:    "Certificate",
				Description: "SSL certificate expiring soon",
				Severity:    "Medium",
				Evidence:    cert.Subject,
			})
		}
	}
	
	return nil
}

func (s *PassiveScanner) sansExtraction(ctx context.Context) error {
	// Already handled in sslCertAnalysis
	return nil
}

func (s *PassiveScanner) certAuthorityAnalysis(ctx context.Context) error {
	// Certificate authority analysis
	return nil
}

func (s *PassiveScanner) tlsVersionHistory(ctx context.Context) error {
	// TLS version history tracking
	return nil
}

func (s *PassiveScanner) cipherSuiteAnalysis(ctx context.Context) error {
	// Cipher suite analysis
	return nil
}

func (s *PassiveScanner) certRevocationCheck(ctx context.Context) error {
	// Certificate revocation check (OCSP/CRL)
	return nil
}

func (s *PassiveScanner) ctLogMonitoring(ctx context.Context) error {
	// CT log monitoring
	return nil
}
