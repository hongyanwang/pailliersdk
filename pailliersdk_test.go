package pailliersdk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"math/big"
	"strconv"
	"testing"
)

var (
	testBit = 1024
	prvkey string
	pubkey string
	plaintext1 = 15
	plaintext2 = 20
	scaler = 2
	ciphertext1 string
	ciphertext2 string
	cipherMul string
	cipherExp string
	commitment1 string
	commitment2 string
	owner = "Rx3Cihj8SJgrYaPgPj1XpodfHxUQXUxKi"
	user = "ZsPy7eELS55MXALUhAynUtjsxjeKFbwqy"
	client = NewPaillierClient()
)

// 公私钥信息
const admin_pk = "040bf4ab3b2918fd62ac0f7a718c24f68e7f31c44d4f874580eab031619aeb0fe29471bf2a52ecf14cbcadc1d5d65188d25bb9a274f5dcf44e460e4e364c6b1c94"
const admin_sk_D = "ea07ded1156e152ef8615661581cf73495c33b431f3fbe372f57370dc80b375b"
const admin_sk_X = "0bf4ab3b2918fd62ac0f7a718c24f68e7f31c44d4f874580eab031619aeb0fe2"
const admin_sk_Y = "9471bf2a52ecf14cbcadc1d5d65188d25bb9a274f5dcf44e460e4e364c6b1c94"

func getPrivateKey() *ecdsa.PrivateKey {
	d, _ := big.NewInt(0).SetString(admin_sk_D, 16)
	x, _ := big.NewInt(0).SetString(admin_sk_X, 16)
	y, _ := big.NewInt(0).SetString(admin_sk_Y, 16)
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		},
		D: d,
	}
}

// test paillier client method
func TestKeyGen(t *testing.T) {
	keyGenData := map[string]int{
		"secbit": testBit,
	}
	data,_ := json.Marshal(keyGenData)
	caller := &FuncCaller{
		Method:  "PaillierKeyGen",
		Args:    string(data),
		Address: owner,
	}
	data,_ = json.Marshal(caller)
	// call paillier and encrypt testdata
	result, err := client.Submit("paillier", string(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)

	// get two ciphertexts
	var resMap map[string]string
	err = json.Unmarshal([]byte(result), &resMap)
	if err != nil {
		t.Fatal(err)
	}
	prvkey = resMap["privateKey"]
	pubkey = resMap["publicKey"]

	t.Logf("private key: %s\n", prvkey)
	t.Logf("public key: %s\n", pubkey)
}

func TestEnc(t *testing.T) {
	encData1 := map[string]string{
		"message": strconv.Itoa(plaintext1),
		"publicKey": pubkey,
	}
	data,_ := json.Marshal(encData1)
	caller := &FuncCaller{
		Method:  "PaillierEnc",
		Args:    string(data),
		Address: owner,
	}
	data,_ = json.Marshal(caller)
	// call paillier and encrypt plaintext1
	result, err := client.Submit("paillier", string(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)

	// get ciphertext1
	var resMap map[string]string
	err = json.Unmarshal([]byte(result), &resMap)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext1 = resMap["ciphertext"]

    // encrypt plaintext2
	encData2 := map[string]string{
		"message": strconv.Itoa(plaintext2),
		"publicKey": pubkey,
	}
	data,_ = json.Marshal(encData2)
	caller2 := &FuncCaller{
		Method:  "PaillierEnc",
		Args:    string(data),
		Address: owner,
	}
	data,_ = json.Marshal(caller2)
	// call paillier and encrypt plaintext2
	result, err = client.Submit("paillier", string(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)

	// get ciphertext2
	err = json.Unmarshal([]byte(result), &resMap)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2 = resMap["ciphertext"]

	t.Logf("ciphertext1: %s\n", ciphertext1)
	t.Logf("ciphertext2: %s\n", ciphertext2)
}

func TestDec(t *testing.T) {
	decData := map[string]string{
		"ciphertext": ciphertext1,
		"publicKey": pubkey,
		"privateKey": prvkey,
	}
	data,_ := json.Marshal(decData)
	caller := &FuncCaller{
		Method:  "PaillierDec",
		Args:    string(data),
		Address: owner,
	}
	data,_ = json.Marshal(caller)
	// call paillier and decrypt testdata
	result, err := client.Submit("paillier", string(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)

	// get plaintext
	var resMap map[string]uint64
	err = json.Unmarshal([]byte(result), &resMap)
	if err != nil {
		t.Fatal(err)
	}
	plain := resMap["plaintext"]
	t.Logf("decrypted ciphertext1: %d\n", plain)
}

func TestMul(t *testing.T) {
	ecdsaPrvkey := getPrivateKey()
	commitment1 = Commit(ecdsaPrvkey, ciphertext1, user)
	commitment2 = Commit(ecdsaPrvkey, ciphertext2, user)
	mulData := map[string]string{
		"publicKey": pubkey,
		"ciphertext1": ciphertext1,
		"commitment1": commitment1,
		"ciphertext2": ciphertext2,
		"commitment2": commitment2,
	}
	data,_ := json.Marshal(mulData)
	caller := &FuncCaller{
		Method:  "PaillierMul",
		Args:    string(data),
		Address: user,
	}
	data,_ = json.Marshal(caller)
	// call paillier and multiply ciphertext
	result, err := client.Submit("paillier", string(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)

	// get ciphetext
	var resMap map[string]string
	err = json.Unmarshal([]byte(result), &resMap)
	if err != nil {
		t.Fatal(err)
	}

	cipherMul := resMap["ciphertext"]
	t.Logf("multiplication of two ciphertexts: %s\n", cipherMul)
	mulRes :=  PaillierDec(cipherMul, pubkey, prvkey)
	t.Logf("decrypted cipherMul: %d\n", mulRes)
}

func TestExp(t *testing.T) {
	expData := map[string]string{
		"publicKey": pubkey,
		"ciphertext": ciphertext1,
		"commitment": commitment1,
		"scalar": strconv.Itoa(scaler),
	}
	data,_ := json.Marshal(expData)
	caller := &FuncCaller{
		Method:  "PaillierExp",
		Args:    string(data),
		Address: user,
	}
	data,_ = json.Marshal(caller)
	// call paillier and multiply ciphertext
	result, err := client.Submit("paillier", string(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(result)

	// get ciphetext
	var resMap map[string]string
	err = json.Unmarshal([]byte(result), &resMap)
	if err != nil {
		t.Fatal(err)
	}

	cipherExp := resMap["ciphertext"]
	t.Logf("exponentiation of ciphertext1 and %d: %s\n", scaler, cipherExp)
	expRes :=  PaillierDec(cipherExp, pubkey, prvkey)
	t.Logf("decrypted cipherExp: %d\n", expRes)
}
