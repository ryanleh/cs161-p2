package userlib

import (
	"fmt"
	"os"
	"strings"
	"time"

	"io"

	"crypto"
	"crypto/rsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/ecdsa"
	"crypto/aes"
	"crypto/cipher"
	"hash"

	"github.com/deckarep/golang-set"
	"golang.org/x/crypto/argon2"
        "github.com/google/uuid"
)

type UUID = uuid.UUID

type PKEEncKey struct {
	keyType UUID
	pubKey rsa.PublicKey
}

type PKEDecKey struct {
	keyType UUID
	privKey rsa.PrivateKey
}

type DSSignKey struct {
	keyType UUID
	privKey rsa.PrivateKey
}

type DSVerifyKey struct {
	keyType UUID
	pubKey rsa.PublicKey
}

type PK struct {
	keyType UUID
	pubKey rsa.PublicKey
}

// AES blocksize.
var AESBlockSize = aes.BlockSize

// Hash/MAC size
var HashSize = sha512.Size

// AES keysize
var AESKeySize = 16


// Debug print true/false
var DebugPrint = false

// DebugMsg. Helper function: Does formatted printing to stderr if
// the DebugPrint global is set.  All our testing ignores stderr,
// so feel free to use this for any sort of testing you want.
func DebugMsg(format string, args ...interface{}) {
	if DebugPrint {
		msg := fmt.Sprintf("%v ", time.Now().Format("15:04:05.00000"))
		fmt.Fprintf(os.Stderr,
			msg+strings.Trim(format, "\r\n ")+"\n", args...)
	}
}

// RandBytes. Helper function: Returns a byte slice of the specificed
// size filled with random data
func RandBytes(bytes int) (data []byte) {
	data = make([]byte, bytes)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
	return
}

var datastore = make(map[UUID][]byte)
var keystore = make(map[UUID]PK)

//var 

/*
********************************************
**           Datastore Functions          **
**       DatastoreSet, DatastoreGet,      **
**     DatastoreDelete, DatastoreClear    **
********************************************
*/

// Sets the value in the datastore
func DatastoreSet(key string, value []byte) {
	foo := make([]byte, len(value))
	copy(foo, value)

	datastore[key] = foo
}

// Returns the value if it exists
func DatastoreGet(key string) (value []byte, ok bool) {
	value, ok = datastore[key]
	if ok && value != nil {
		foo := make([]byte, len(value))
		copy(foo, value)
		return foo, ok
	}
	return
}

// Deletes a key
func DatastoreDelete(key string) {
	delete(datastore, key)
}

// Use this in testing to reset the datastore to empty
func DatastoreClear() {
	datastore = make(map[string][]byte)
}

func KeystoreClear() {
	keystore = make(map[string]interface{})
}

func KeystoreSet(key string, value PK) {
	keystore[key] = value
}

func KeystoreGet(key string) (value interface{}, ok bool) {
	value, ok = keystore[key]
	return
}

// Use this in testing to get the underlying map if you want
// to play with the datastore.
func DatastoreGetMap() map[string][]byte {
	return datastore
}

// Use this in testing to get the underlying map if you want 
// to play with the keystore.
func KeystoreGetMap() map[string]rsa.PublicKey {
	return keystore
}


/*
********************************************
**         Public Key Encryption          **
**       PKEKeyGen, PKEEnc, PKEDec        **
********************************************
*/

// Generates a key pair for public-key encryption via RSA
func PKEKeyGen() (PKEEncKey, PKEDecKey, error) {
	RSAPrivKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	RSAPubKey := RSAPrivKey.PublicKey

	var PKEEncKeyRes PKEEncKey
	PKEEncKeyRes.keyType = "PKE"
	PKEEncKeyRes.pubKey = RSAPubKey

	var PKEDecKeyRes PKEDecKey
	PKEDecKeyRes.keyType = "PKE"
	PKEDecKeyRes.privKey = RSAPrivKey

	return PKEEncKeyRes, PKEDecKeyRes, err
}

// Encrypts a byte stream via RSA-OAEP / sha256 as hash
func PKEEnc(ek PKEEncKey, plaintext []byte) ([]byte, error) {
	RSAPubKey := ek.RSAPubKey

	if ek.keyType != "PKE" {
		return nil, errors.New("Using a non-PKE key for PKE.")
	}

	ciphertext, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, RSAPubKey, plaintext, nil)

	return ciphertext, err
}

// Decrypts a byte stream
func PKEDec(dk PKEDecKey, ciphertext []byte) ([]byte, error) {
	RSAPrivKey := dk.RSAPrivKey

	if dk.RSAKeyType != "PKE" {
		return nil, errors.New("Using a non-PKE key for PKE.")
	}

	plaintext, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, RSAPrivKey, ciphertext, nil)
}

/*
********************************************
**           Digital Signature            **
**       DSKeyGen, DSSign, DSVerify       **
********************************************
*/

// Generates a key pair for digital signature via RSA
func DSKeyGen() (DSSignKey, DSVerifyKey, error) {
	RSAPrivKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	RSAPubKey := RSAPrivKey.PublicKey

	var DSSignKeyRes  DSSignKey
	DSSignKeyRes.keyType = "DS"
	DSSignKeyRes.privKey = RSAPrivKey

	var DSVerifyKeyRes DSVerifyKey
	DSSignKeyRes.keyType = "DS"
	DSSignKeyRes.pubKey = RSAPubKey

	return DSSignKey, DSVerifyKey, err
}

// Signs a byte stream via SHA256 and PKCS1v15
func DSSign(sk DSSignKey, msg []byte) ([]byte, error) {
	RSAPrivKey := sk.privKey

	if sk.keyType != "DS" {
		return nil, errors.New("Using a non-DS key for DS.")
	}

	hashed := sha512.Sum512(msg)
	return rsa.SignPKCS1v15(rand.Reader, RSAPrivKey, crypto.SHA512, hashed[:])
}

// Verifies a signature
func DSVerify(vk DSVerifyKey, msg []byte, sig []byte) error {
	RSAPubKey := vk.pubKey

	if vk.RSAKeyType != "DS" {
		return nil, errors.New("Using a non-DS key for DS.")
	}

	hashed := sha512.Sum512(msg)
	return rsa.SignPKCS1v15(rand.Reader, RSAPubKey, crypto.SHA512, hashed[:])
}

/*
********************************************
**                 MAC                    **
**          MACEval, MACEqual             **
********************************************
*/

// Eval the MAC
func MACEval(key []byte, msg []byte) []byte {
	h = hmac.New(sha512.New, key)
	h.Write(msg)
	res := h.Sum(nil)

	return res
}

// Equals comparison for hashes/MACs
// Does NOT leak timing.
func MACEqual(a []byte, b []byte) bool {
	return hmac.Equal(a, b)
}


/*
********************************************
**               KDF                      **
**            KDFNewKey                   **
********************************************
*/

func KDFNewKey (seed []byte, info interface{}) ([]byte, error) {
	mixed := []interface{}{seed, info, "MAC"}

	json_mixed, err := json.Marshal(mixed)

	h := sha512.Sum512(json_mixed)
	res := h[0:16]

	return res, err
}

// Argon2:  Automatically choses a decent combination of iterations and memory
func Argon2Key(password []byte, salt []byte,
	keyLen uint32) []byte {
	return argon2.IDKey(password, salt,
		1,
		64*1024,
		4,
		keyLen)
}


/*
********************************************
**        Symmetric Encryption            **
**           SymEnc, SymDec               **
********************************************
*/

// Gets a stream cipher object for AES
// Length of iv should be == BlockSize
func SymEnc(key []byte, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return cipher.NewCFBEncrypter(block, iv)
}

func SymDec(key []byte, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return cipher.NewCFBDecrypter(block, iv)
}
