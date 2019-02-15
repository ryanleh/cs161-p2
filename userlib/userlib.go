package userlib

import (
    "fmt"
    "os"
    "strings"
    "time"
    "errors"

    "io"
    "encoding/json"

    "crypto"
    "crypto/rsa"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha512"
    "crypto/aes"
    "crypto/cipher"

    "golang.org/x/crypto/argon2"
    "github.com/google/uuid"
)

type UUID = uuid.UUID

type PKEEncKey struct {
    keyType string
    pubKey rsa.PublicKey
}

type PKEDecKey struct {
    keyType string
    privKey rsa.PrivateKey
}

type DSSignKey struct {
    keyType string
    privKey rsa.PrivateKey
}

type DSVerifyKey struct {
    keyType string
    pubKey rsa.PublicKey
}

type PK struct {
    keyType string
    pubKey rsa.PublicKey
}

// RSA keysize
var RSAKeySize = 2048

// AES constants
var AESBlockSize = aes.BlockSize
var AESKeySize = 16

// Hash/MAC size
var HashSize = sha512.Size


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

var datastore map[UUID][]byte = make(map[UUID][]byte)
var keystore map[UUID]rsa.PublicKey = make(map[UUID]rsa.PublicKey)

//var 

/*
********************************************
**           Datastore Functions          **
**       DatastoreSet, DatastoreGet,      **
**     DatastoreDelete, DatastoreClear    **
********************************************
*/

// Sets the value in the datastore
func DatastoreSet(key UUID, value []byte) {
    foo := make([]byte, len(value))
    copy(foo, value)

    datastore[key] = foo
}

// Returns the value if it exists
func DatastoreGet(key UUID) (value []byte, ok bool) {
    value, ok = datastore[key]
    if ok && value != nil {
        foo := make([]byte, len(value))
        copy(foo, value)
        return foo, ok
    }
    return
}

// Deletes a key
func DatastoreDelete(key UUID) {
    delete(datastore, key)
}

// Use this in testing to reset the datastore to empty
func DatastoreClear() {
    datastore = make(map[UUID][]byte)
}

func KeystoreClear() {
    keystore = make(map[UUID]rsa.PublicKey)
}

func KeystoreSet(key UUID, value rsa.PublicKey) {
    keystore[key] = value
}

func KeystoreGet(key UUID) (value rsa.PublicKey, ok bool) {
    value, ok = keystore[key]
    return
}

// Use this in testing to get the underlying map if you want
// to play with the datastore.
func DatastoreGetMap() map[UUID][]byte {
    return datastore
}

// Use this in testing to get the underlying map if you want 
// to play with the keystore.
func KeystoreGetMap() map[UUID]rsa.PublicKey {
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
    PKEDecKeyRes.privKey = *RSAPrivKey

    return PKEEncKeyRes, PKEDecKeyRes, err
}

// Encrypts a byte stream via RSA-OAEP / sha256 as hash
func PKEEnc(ek PKEEncKey, plaintext []byte) ([]byte, error) {
    RSAPubKey := &ek.pubKey

    if ek.keyType != "PKE" {
        return nil, errors.New("Using a non-PKE key for PKE.")
    }

    ciphertext, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, RSAPubKey, plaintext, nil)

    return ciphertext, err
}

// Decrypts a byte stream
func PKEDec(dk PKEDecKey, ciphertext []byte) ([]byte, error) {
    RSAPrivKey := &dk.privKey

    if dk.keyType != "PKE" {
        return nil, errors.New("Using a non-PKE key for PKE.")
    }

    plaintext, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, RSAPrivKey, ciphertext, nil)

    return plaintext, err
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

    var DSSignKeyRes DSSignKey
    DSSignKeyRes.keyType = "DS"
    DSSignKeyRes.privKey = *RSAPrivKey

    var DSVerifyKeyRes DSVerifyKey
    DSVerifyKeyRes.keyType = "DS"
    DSVerifyKeyRes.pubKey = RSAPubKey

    return DSSignKeyRes, DSVerifyKeyRes, err
}

// Signs a byte stream via SHA256 and PKCS1v15
func DSSign(sk DSSignKey, msg []byte) ([]byte, error) {
    RSAPrivKey := &sk.privKey

    if sk.keyType != "DS" {
        return nil, errors.New("Using a non-DS key for DS.")
    }

    hashed := sha512.Sum512(msg)

    sig, err := rsa.SignPKCS1v15(rand.Reader, RSAPrivKey, crypto.SHA512, hashed[:])

    return sig, err
}

// Verifies a signature
func DSVerify(vk DSVerifyKey, msg []byte, sig []byte) error {
    RSAPubKey := &vk.pubKey

    if vk.keyType != "DS" {
        return errors.New("Using a non-DS key for DS.")
    }

    hashed := sha512.Sum512(msg)

    err := rsa.VerifyPKCS1v15(RSAPubKey, crypto.SHA512, hashed[:], sig)

    return err
}

/*
********************************************
**                 MAC                    **
**          MACEval, MACEqual             **
********************************************
*/

// Eval the MAC
func MACEval(key []byte, msg []byte) []byte {
    mac := hmac.New(sha512.New, key)
    mac.Write(msg)
    res := mac.Sum(nil)

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
func Argon2Key(password []byte, salt []byte, keyLen uint32) []byte {
    return argon2.IDKey(password, salt, 1, 64*1024, 4, keyLen)
}


/*
********************************************
**        Symmetric Encryption            **
**           SymEnc, SymDec               **
********************************************
*/

// Gets a stream cipher object for AES
// Length of iv should be == AESBlockSize
func SymEnc(key []byte, iv []byte, plaintext []byte) []byte {
    if len(iv) != AESBlockSize {
        panic("IV length not equal to AES bloc size")
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }

    stream := cipher.NewCTR(block, iv)
    ciphertext := make([]byte, AESBlockSize + len(plaintext))
    copy(ciphertext[:AESBlockSize], iv)

    stream.XORKeyStream(ciphertext[AESBlockSize:], plaintext)

    return ciphertext
}

func SymDec(key []byte, iv []byte, ciphertext []byte) []byte {
    return SymEnc(key, iv, ciphertext)
}
