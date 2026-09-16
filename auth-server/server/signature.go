package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// SupportedAlgorithms is every JWS algorithm this server can verify. RS256 is
// the historical default; ES256 and PS256 let a provider or resource client
// that doesn't sign with RSA/RS256 still be used.
var SupportedAlgorithms = []string{"RS256", "PS256", "ES256"}

func validAlgorithm(alg string) bool {
	return contains(SupportedAlgorithms, alg)
}

// verifySignature checks a JOSE compact-serialization signature against a
// public key, dispatching on the JWT "alg" header value. signingInput is the
// ASCII "header.payload" the signature covers.
//
// ES256's signature is the raw 64-byte r||s concatenation defined by RFC 7518
// section 3.4 (JWS), not the ASN.1 DER encoding crypto/ecdsa's own Sign/Verify
// helpers produce — decoding it as DER, or via ecdsa.VerifyASN1, is a common
// and silent mistake that would reject every genuine ES256 token.
func verifySignature(alg string, key crypto.PublicKey, signingInput, signature []byte) error {
	digest := sha256.Sum256(signingInput)
	switch alg {
	case "RS256":
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("RS256 requires an RSA public key")
		}
		return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], signature)
	case "PS256":
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("PS256 requires an RSA public key")
		}
		return rsa.VerifyPSS(rsaKey, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	case "ES256":
		ecKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("ES256 requires an EC public key")
		}
		if len(signature) != 64 {
			return errors.New("ES256 signature must be 64 bytes (raw r||s, not ASN.1 DER)")
		}
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if !ecdsa.Verify(ecKey, digest[:], r, s) {
			return errors.New("ES256 signature is invalid")
		}
		return nil
	default:
		return fmt.Errorf("unsupported algorithm %q", alg)
	}
}

// keyMatchesAlgorithm reports whether a parsed public key's type is
// compatible with the given JWS algorithm, so a registration (a resource
// client's key, or a JWKS entry) can be rejected up front instead of failing
// confusingly the first time it's used.
func keyMatchesAlgorithm(alg string, key crypto.PublicKey) bool {
	switch alg {
	case "RS256", "PS256":
		_, ok := key.(*rsa.PublicKey)
		return ok
	case "ES256":
		_, ok := key.(*ecdsa.PublicKey)
		return ok
	default:
		return false
	}
}
