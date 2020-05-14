package pailliersdk

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -L${SRCDIR}/lib -lpaillier -lgmp

#include "paillier.h"
#include "gmp.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
*/
import "C"
import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"sync"
	"unsafe"
	"github.com/hongyanwang/pailliersdk/xchain_plugin/pb"
)

var get_rand = (*[0]byte)(unsafe.Pointer(C.paillier_get_rand_devurandom))
var secbit  int
//var length = secbit/4
var length int

type PaillierClient struct {}
var kInstance *PaillierClient
var once sync.Once
func NewPaillierClient() *PaillierClient {
	if kInstance != nil {
		return kInstance
	}
	once.Do(func() {
		kInstance = &PaillierClient{}
	})
	return kInstance
}

func (s *PaillierClient) Submit(method string, inputs string) (string, error) {
	if method != "paillier" {
		return "", errors.New("submit error, wrong method, supposed to be paillier")
	}

	var caller FuncCaller
	err := json.Unmarshal([]byte(inputs), &caller)
	if err != nil {
		return "", errors.New("submit error, unmarshal inputs error")
	}

	var resMapStr string
	switch caller.Method {
	case "KeyGen":
		resMapStr, err = KeyGenToMap(caller)
	case "PaillierEnc":
		resMapStr, err = PaillierEncToMap(caller)
	case "PaillierDec":
		resMapStr, err = PaillierDecToMap(caller)
	case "PaillierMul":
		resMapStr, err = PaillierMulToMap(caller)
	case "PaillierExp":
		resMapStr, err = PaillierExpToMap(caller)
	default:
		return "", errors.New("submit error, invalid paillier method")
	}

	if err != nil {
		return "", fmt.Errorf("submit error,  %v", err)
	}

	return resMapStr,nil
}

// wrap method outputs to map
//TODO: verify signature and commitment
func KeyGenToMap(caller FuncCaller) (string, error){
	if caller.Args == "" {
		return "", errors.New("KeyGen errors, args nil")
	}
	var params pb.KeyGenParams
	json.Unmarshal([]byte(caller.Args), &params)
	prvkey, pubkey := KeyGen(int(params.Secbit))
	outputs := pb.KeyGenOutputs{
		PrivateKey: prvkey,
		PublicKey: pubkey,
	}

	resStr,err := json.Marshal(outputs)
	if err!=nil {
		return "", errors.New("KeyGen errors, marshal result error")
	}
	return string(resStr), nil
}

func PaillierEncToMap(caller FuncCaller) (string, error){
	if caller.Args == "" {
		return "", errors.New("PaillierEnc errors, args nil")
	}
	var params pb.PaillierEncParams
	json.Unmarshal([]byte(caller.Args), &params)
	msg,_  := strconv.Atoi(params.Message)
	cipher := PaillierEnc(uint32(msg), params.PublicKey)
	outputs := pb.PaillierEncOutputs{
		Ciphertext: cipher,
	}

	resStr,err := json.Marshal(outputs)
	if err!=nil {
		return "", errors.New("PaillierEnc errors, marshal result error")
	}
	return string(resStr), nil
}


func PaillierDecToMap(caller FuncCaller) (string, error){
	if caller.Args == "" {
		return "", errors.New("PaillierDec errors, args nil")
	}
	var params pb.PaillierDecParams
	json.Unmarshal([]byte(caller.Args), &params)

	plain := PaillierDec(params.Ciphertext, params.PublicKey, params. PrivateKey)
	outputs := pb.PaillierDecOutputs{
		Plaintext: plain,
	}

	resStr,err := json.Marshal(outputs)
	if err!=nil {
		return "", errors.New("PaillierDec errors, marshal result error")
	}
	return string(resStr), nil
}


func PaillierMulToMap(caller FuncCaller) (string, error){
	if caller.Args == "" {
		return "", errors.New("PaillierMul errors, args nil")
	}
	var params pb.PaillierMulParams
	json.Unmarshal([]byte(caller.Args), &params)


	cipher := PaillierMul(params.PublicKey, params.Ciphertext1, params.Ciphertext2)
	outputs := pb.PaillierMulOutputs{
		Ciphertext: cipher,
	}

	resStr,err := json.Marshal(outputs)
	if err!=nil {
		return "", errors.New("PaillierMul errors, marshal result error")
	}
	return string(resStr), nil
}


func PaillierExpToMap(caller FuncCaller) (string, error){
	if caller.Args == "" {
		return "", errors.New("PaillierExp errors, args nil")
	}
	var params pb.PaillierExpParams
	json.Unmarshal([]byte(caller.Args), &params)

	scalarInput,_ := strconv.Atoi(params.Scalar)
	cipher := PaillierExp(params.PublicKey, params.Ciphertext, uint32(scalarInput))
	outputs := pb.PaillierExpOutputs{
		Ciphertext: cipher,
	}

	resStr,err := json.Marshal(outputs)
	if err!=nil {
		return "", errors.New("PaillierExp errors, marshal result error")
	}
	return string(resStr), nil
}

// paillier encryption method
/*
void paillier_keygen(int modulusbits,
					 paillier_pubkey_t** pub,
					 paillier_prvkey_t** prv,
					 paillier_get_rand_t get_rand )
 */
func KeyGen(secbitinput int) (prv string, pub string){
	secbit = secbitinput
	length = secbit/4

	var pubkey_c *C.paillier_pubkey_t
	var prvkey_c *C.paillier_prvkey_t
	C.paillier_keygen(C.int(secbit), &pubkey_c, &prvkey_c, get_rand)
	prvHex := C.paillier_prvkey_to_hex(prvkey_c)
	pubHex := C.paillier_pubkey_to_hex(pubkey_c)

	C.paillier_freepubkey(pubkey_c)
	C.paillier_freeprvkey(prvkey_c)
	return C.GoString(prvHex), C.GoString(pubHex)
}

//paillier_ciphertext_t* paillier_enc(paillier_ciphertext_t* res,
//									  paillier_pubkey_t* pub,
//									  paillier_plaintext_t* pt,
//									  paillier_get_rand_t get_rand )
func PaillierEnc(msg uint32, pubkey string) string{
	var pubkey_c *C.paillier_pubkey_t
	var pt *C.paillier_plaintext_t
	var ct *C.paillier_ciphertext_t
	var len = C.int(length)

	pubkey_c = C.paillier_pubkey_from_hex(C.CString(pubkey))
	pt = C.paillier_plaintext_from_ui(C.ulong(msg))
	// encrypt with pubkey
	ct = C.paillier_enc(ct, pubkey_c, pt, get_rand)
	// convert ciphertext to bytes
	ctVoid := C.paillier_ciphertext_to_bytes(len, ct)
	ctBytes := C.GoBytes(ctVoid, len)

	C.paillier_freepubkey(pubkey_c)
	C.paillier_freeplaintext(pt)
	C.paillier_freeciphertext(ct)

	return hex.EncodeToString(ctBytes)
}

//paillier_plaintext_t* paillier_dec(paillier_plaintext_t* res,
//									 paillier_pubkey_t* pub,
//							 		 paillier_prvkey_t* prv,
//							 		 paillier_ciphertext_t* ct );
func PaillierDec(cipher, pubkey, prvkey string) uint64{
	var pubkey_c *C.paillier_pubkey_t
	var prvkey_c *C.paillier_prvkey_t
	var pt *C.paillier_plaintext_t
	var ct *C.paillier_ciphertext_t
	var len = C.int(length)

	pubkey_c = C.paillier_pubkey_from_hex(C.CString(pubkey))
	prvkey_c = C.paillier_prvkey_from_hex(C.CString(prvkey), pubkey_c)
	ctBytes,_ := hex.DecodeString(cipher)
	ctVoid :=  C.CBytes(ctBytes)
	ct = C.paillier_ciphertext_from_bytes(ctVoid, len)
	// decrypt with prvkey
	pt = C.paillier_dec(pt, pubkey_c, prvkey_c, ct)

	// convert plaintext to bytes
	ptVoid := C.paillier_plaintext_to_bytes(len, pt)
	ptBytes := C.GoBytes(ptVoid, len)

	C.paillier_freepubkey(pubkey_c)
	C.paillier_freeprvkey(prvkey_c)
	C.paillier_freeplaintext(pt)
	C.paillier_freeciphertext(ct)

	ptHex := hex.EncodeToString(ptBytes)
	ptInt,_ := new(big.Int).SetString(ptHex, 16)
	return ptInt.Uint64()
}

//void paillier_mul(paillier_pubkey_t* pub,
//					paillier_ciphertext_t* res,
//					paillier_ciphertext_t* ct0,
//					paillier_ciphertext_t* ct1 );
func PaillierMul(pubkey, cipher1, cipher2 string) string{
	var pubkey_c *C.paillier_pubkey_t
	var ct1 *C.paillier_ciphertext_t
	var ct2 *C.paillier_ciphertext_t
	var len = C.int(length)

	pubkey_c = C.paillier_pubkey_from_hex(C.CString(pubkey))
	ct1Bytes,_ := hex.DecodeString(cipher1)
	ct1Void :=  C.CBytes(ct1Bytes)
	ct2Bytes,_ := hex.DecodeString(cipher2)
	ct2Void :=  C.CBytes(ct2Bytes)
	ct1 = C.paillier_ciphertext_from_bytes(ct1Void, len)
	ct2 = C.paillier_ciphertext_from_bytes(ct2Void, len)
	// multiply using pubkey and two ciphertexts
	C.paillier_mul(pubkey_c, ct2, ct1, ct2)

	// convert result ciphertext to bytes
	resVoid := C.paillier_ciphertext_to_bytes(len, ct2)
	resBytes := C.GoBytes(resVoid, len)

	C.paillier_freepubkey(pubkey_c)
	C.paillier_freeciphertext(ct1)
	C.paillier_freeciphertext(ct2)

	return hex.EncodeToString(resBytes)
}

//void paillier_exp(paillier_pubkey_t* pub,
//					paillier_ciphertext_t* res,
//					paillier_ciphertext_t* ct,
//					paillier_plaintext_t* pt )
func PaillierExp(pubkey, cipher string, plain uint32) string{
	var pubkey_c *C.paillier_pubkey_t
	var pt *C.paillier_plaintext_t
	var ct *C.paillier_ciphertext_t
	var len = C.int(length)

	pubkey_c = C.paillier_pubkey_from_hex(C.CString(pubkey))
	pt = C.paillier_plaintext_from_ui(C.ulong(plain))
	ct1Bytes,_ := hex.DecodeString(cipher)
	ct1Void :=  C.CBytes(ct1Bytes)
	ct = C.paillier_ciphertext_from_bytes(ct1Void, len)
	// multiply ciphertext by a plaintext number
	C.paillier_exp(pubkey_c, ct, ct, pt)

	// convert result ciphertext to bytes
	resVoid := C.paillier_ciphertext_to_bytes(len, ct)
	resBytes := C.GoBytes(resVoid, len)

	C.paillier_freepubkey(pubkey_c)
	C.paillier_freeplaintext(pt)
	C.paillier_freeciphertext(ct)

	return hex.EncodeToString(resBytes)
}
