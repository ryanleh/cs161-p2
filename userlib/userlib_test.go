package userlib
import "testing"

// You can import other stuff in here if you want.

//import "encoding/hex"
//import "io"

// Golang has a very powerful routine for building tests.

// Run with "go test" to run the tests

// And "go test -v" to run verbosely so you see all the logging and
// what tests pass/fail individually.

// And "go test -cover" to check your code coverage in your tests


func TestDatastore(t *testing.T){
	DatastoreSet("foo", []byte("bar"))
	data, valid := DatastoreGet("bar")
	if valid {
		t.Error("Improper fetch")
	}
	data, valid = DatastoreGet("foo")
	if !valid || string(data) != "bar" {
		t.Error("Improper fetch")
	}
	t.Log("Datastore fetch", data)
	t.Log("Datastore map", DatastoreGetMap())
	DatastoreClear()
	t.Log("Datastore map", DatastoreGetMap())
}

func TestRSA(t *testing.T){
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
		[] byte ("Squeamish Ossifrage"),
		[] byte ("Tag"))
	if err != nil {
		t.Error("got error", err)
	}
	decrypt, err := RSADecrypt(key,
		bytes, [] byte("Tag"))
	if err != nil || (string(decrypt) != "Squeamish Ossifrage"){
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

// An example of deliberately failing test
// func TestFailure(t *testing.T){
//	t.Log("This test will fail")
//	t.Error("Test of failure")
//}
