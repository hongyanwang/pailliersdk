package pailliersdk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
)

var curve = elliptic.P256()

// ECDSASignature is the structure for marshall signature
type ECDSASignature struct {
	R, S *big.Int
}

func Commit(prvkey *ecdsa.PrivateKey, cipher, user string) string {
	msg := cipher + user
	hash := sha256.Sum256([]byte(msg))
	pk := prvkey.PublicKey
	pubkey := elliptic.Marshal(pk.Curve, pk.X, pk.Y)
	r, s, _ := ecdsa.Sign(rand.Reader, prvkey, hash[:])
	sigRS := ECDSASignature{r, s}
	sig,_ := asn1.Marshal(sigRS)

	commitment := make([]byte, 65+len(sig))
	copy(commitment[0:], pubkey)
	copy(commitment[65:], sig)
	return base64.RawStdEncoding.EncodeToString(commitment)
}

// authorization check
func CheckCommitment(cipher, user, commitment string) bool {
	commData,_ := base64.RawStdEncoding.DecodeString(commitment)
	hash := sha256.Sum256([]byte(cipher+user))

	x,y := elliptic.Unmarshal(curve, commData[:65])
	pub := &ecdsa.PublicKey{curve, x, y}
	sig := commData[65:]
	sigRS := new(ECDSASignature)
	asn1.Unmarshal(sig, sigRS)

	return ecdsa.Verify(pub, hash[:], sigRS.R, sigRS.S)
}
