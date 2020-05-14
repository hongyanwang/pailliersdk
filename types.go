package pailliersdk

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
)

type FuncCaller struct {
    Method string  `json:"method"`
    Args string     `json:"args"`
    Address string `json:"address"`
    PublicKey string `json:"public_key"`
    Signature string `json:"signature"`
}

func(k* FuncCaller) Sign(sk *ecdsa.PrivateKey) (*FuncCaller, error) {
     msg := k.Method + k.Args
     hash := sha256.Sum256([]byte(msg))
     sig, err := sk.Sign(rand.Reader, hash[:], nil)
     if err != nil {
	 return k, err
     }
     pk := sk.PublicKey
     k.PublicKey = hex.EncodeToString(elliptic.Marshal(pk.Curve, pk.X, pk.Y))
     k.Signature = hex.EncodeToString(sig)
     return k, nil
}

