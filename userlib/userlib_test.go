package userlib

import "testing"
// import "encoding/hex"
import "github.com/google/uuid"

// Golang has a very powerful routine for building tests.

// Run with "go test" to run the tests

// And "go test -v" to run verbosely so you see all the logging and
// what tests pass/fail individually.

// And "go test -cover" to check your code coverage in your tests

// Default test strings
var key1 []byte = []byte("cs161teststring1")
var key2 []byte = []byte("cs161teststring2")
var key3 []byte = []byte("cs161teststring3")
var key4 []byte = []byte("cs161teststring4")
var key5 []byte = []byte("cs161teststring5")

// Creates a UUID from the supplied bytes
// Use for testing only!
func UUIDFromBytes(t *testing.T, b []byte) (u UUID) {
    u, err := uuid.FromBytes(b)
    if err != nil {
        t.Error("Got FromBytes error:", err)
    }

    return
}

func TestUUIDFromBytesDeterministic(t *testing.T) {
    UUID1 := UUIDFromBytes(t, key1)
    t.Log(UUID1)

    UUID2 := UUIDFromBytes(t, key1)
    t.Log(UUID2)

    if UUID1 != UUID2 {
        t.Error("UUID1 != UUID2")
        t.Log("UUID1:", UUID1)
        t.Log("UUID2:", UUID2)
    }
}

func TestDatastore(t *testing.T) {
    UUID1 := UUIDFromBytes(t, key1)
    UUID2 := UUIDFromBytes(t, key2)
    UUID3 := UUIDFromBytes(t, key3)

    DatastoreSet(UUID1, []byte("foo"))

    _, valid := DatastoreGet(UUID3)
    if valid {
        t.Error("Datastore fetched UUID3 when it wasn't supposed to")
    }

    data, valid := DatastoreGet(UUID1)
    if !valid || string(data) != "foo" {
        t.Error("Error with fetching 'foo' from UUID1")
    }

    _, valid = DatastoreGet(UUID3)
    if valid {
        t.Error("Returned when nothing, oops")
    }

    DatastoreSet(UUID2, []byte("bar"))

    data, valid = DatastoreGet(UUID1)
    if !valid || string(data) != "foo" {
        t.Error("Error with fetching 'foo' from UUID1")
    }

    DatastoreDelete(UUID1)

    _, valid = DatastoreGet(UUID1)
    if valid {
        t.Error("DatastoreGet succeeded even after deleting UUID1")
    }

    data, valid = DatastoreGet(UUID2)
    if !valid || string(data) != "bar" {
        t.Error("Error with fetching 'bar' from UUID2")
    }

    DatastoreClear()

    _, valid = DatastoreGet(UUID2)
    if valid {
        t.Error("DatastoreGet succeeded even after DatastoreClear")
    }

    t.Log("Datastore fetch", data)
    t.Log("Datastore map", DatastoreGetMap())
    DatastoreClear()
    t.Log("Datastore map", DatastoreGetMap())
}

func TestKeystore(t *testing.T) {
    UUID1 := UUIDFromBytes(t, key1)
    UUID2 := UUIDFromBytes(t, key2)
    UUID3 := UUIDFromBytes(t, key3)

    RSAPubKey, _, _ := PKEKeyGen()
    _, DSVerifyKey, _ := DSKeyGen()
    pubKey := RSAPubKey.pubKey
    verKey := DSVerifyKey.pubKey

    KeystoreSet(UUID1, pubKey)
    KeystoreSet(UUID2, verKey)

    _, valid := KeystoreGet(UUID3)
    if valid {
        t.Error("Keystore fetched UUID3 when it wasn't supposed to")
    }

    data, valid := KeystoreGet(UUID1)
    if !valid || data.N.Cmp(pubKey.N) != 0 || data.E != pubKey.E {
        t.Error("Key stored at UUID1 doesn't match")
    }

    data, valid = KeystoreGet(UUID2)
    if !valid || data.N.Cmp(verKey.N) != 0 || data.E != verKey.E {
        t.Error("Key stored at UUID2 doesn't match")
    }

    KeystoreClear()

    _, valid = KeystoreGet(UUID1)
    if valid {
        t.Error("KeystoreGet succeeded even after KeystoreClear")
    }

    t.Log("Keystore fetch", data)
    t.Log("Keystore map", KeystoreGetMap())
    KeystoreClear()
    t.Log("Keystore map", KeystoreGetMap())
}

/*func TestRSA(t *testing.T) {
    key, err := GenerateRSAKey()
    if err != nil {
        t.Error("Got RSA error", err)
    }
    pubkey := key.PublicKey
    KeystoreSet("foo", pubkey)
    val, ok := KeystoreGet("foo")
    if !ok || val != pubkey {
        t.Error("Didn't fetch right")
    }
    _, ok = KeystoreGet("Bar")
    if ok {
        t.Error("Got a key when I shouldn't")
    }
    KeystoreClear()
    KeystoreGetMap()

    bytes, err := RSAEncrypt(&pubkey,
    []byte("Squeamish Ossifrage"),
    []byte("Tag"))
    if err != nil {
        t.Error("got error", err)
    }
    decrypt, err := RSADecrypt(key,
    bytes, []byte("Tag"))
    if err != nil || (string(decrypt) != "Squeamish Ossifrage") {
        t.Error("Decryption failure", err)
    }

    bytes = []byte("Squeamish Ossifrage")
    sign, err := RSASign(key, bytes)
    if err != nil {
        t.Error("RSA sign failure")
    }
    err = RSAVerify(&key.PublicKey, bytes, sign)
    if err != nil {
        t.Error("RSA verification failure")
    }
    bytes[0] = 3
    err = RSAVerify(&key.PublicKey, bytes, sign)
    if err == nil {
        t.Error("RSA verification worked when it shouldn't")
    }
    t.Log("Error return", err)

}

func TestHMAC(t *testing.T) {
    msga := []byte("foo")
    msgb := []byte("bar")
    keya := []byte("baz")
    keyb := []byte("boop")

    mac := NewHMAC(keya)
    mac.Write(msga)
    maca := mac.Sum(nil)
    mac = NewHMAC(keya)
    mac.Write(msgb)
    macb := mac.Sum(nil)
    if Equal(maca, macb) {
        t.Error("MACs are equal for different data")
    }
    mac = NewHMAC(keyb)
    mac.Write(msga)
    macc := mac.Sum(nil)
    if Equal(maca, macc) {
        t.Error("MACs are equal for different key")
    }
    mac = NewHMAC(keya)
    mac.Write(msga)
    macd := mac.Sum(nil)
    if !Equal(maca, macd) {
        t.Error("Macs are not equal when they should be")
    }
}

func TestArgon2(t *testing.T) {
    val1 := Argon2Key([]byte("Password"),
    []byte("nosalt"),
    32)

    val2 := Argon2Key([]byte("Password"),
    []byte("nosalt"),
    64)

    val3 := Argon2Key([]byte("password"),
    []byte("nosalt"),
    32)

    if Equal(val1, val2) || Equal(val1, val3) || Equal(val2, val3) {
        t.Error("Argon2 problem")
    }
    t.Log(hex.EncodeToString(val1))
    t.Log(hex.EncodeToString(val2))
    t.Log(hex.EncodeToString(val3))

}

func TestStreamCipher(t *testing.T) {
    key := []byte("example key 1234")
    msg := "This is a Test"
    ciphertext := make([]byte, BlockSize+len(msg))
    iv := ciphertext[:BlockSize]
    // Load random data
    copy(iv, RandomBytes(BlockSize))

    t.Log("Random IV", hex.EncodeToString(iv))
    cipher := CFBEncrypter(key, iv)
    cipher.XORKeyStream(ciphertext[BlockSize:], []byte(msg))
    t.Log("Message  ", hex.EncodeToString(ciphertext))

    cipher = CFBDecrypter(key, iv)
    // Yes you can do this in-place
    cipher.XORKeyStream(ciphertext[BlockSize:], ciphertext[BlockSize:])
    t.Log("Decrypted messagege", string(ciphertext[BlockSize:]))
    if string(ciphertext[BlockSize:]) != msg {
        t.Error("Decryption failure")
    }
}*/

// Deliberate fail example
// func TestFailure(t *testing.T){
//	t.Log("This test will fail")
//	t.Error("Test of failure")
//}
