package pailliersdk

type FuncCaller struct {
    Method string  `json:"method"`
    Args string     `json:"args"`
    Address string `json:"address"`
    PublicKey string `json:"public_key"`
    Signature string `json:"signature"`
}
