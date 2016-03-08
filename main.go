package main
import (
  "io/ioutil"
  "os"
  "syscall"
  "golang.org/x/crypto/ssh/terminal"
  "github.com/agl/ed25519/edwards25519"
  "crypto/hmac"
  "crypto/sha256"
  "crypto/sha512"
  b64 "encoding/base64"
  "encoding/binary"
)
const (
  PublicKeySize  = 32
  PrivateKeySize = 64
)

func check(e error) {
  if e != nil {
    panic(e)
  }
}

func main() {
  var publicKey = new([32]byte)
  if (len(os.Args[:]) <2) {
    panic("Usage " +os.Args[0]+ " filename")
  }
  // Read file
  filename := os.Args[1]
  dat, ass := ioutil.ReadFile(filename)
  check(ass)
  fmt.Println("Type private key password")
  // ask for hmac password with file
  bytePass, err := terminal.ReadPassword(syscall.Stdin)
  check(err)
  passu := hmac.New(sha256.New, bytePass)
  passu.Write(dat)
  kdfresult :=passu.Sum(nil)
  h := sha512.New()
  h.Write(kdfresult)
  digest := h.Sum(nil)

  //Lowest three are cleared
  digest[0] &= 248
  // Highest bit cleared  of the last
  digest[31] &= 127
  // Second highest bit set of the last
  digest[31] |= 64
  // I is ^c^v:ing from agl ed25519
  var A edwards25519.ExtendedGroupElement
  var hBytes [32]byte
  copy(hBytes[:], digest[:32])
  edwards25519.GeScalarMultBase(&A, &hBytes)
  A.ToBytes(publicKey)
  var pubkeystat [32]byte
  pubkeystat=*publicKey
  var privkey [64]byte
  copy(privkey[32:],pubkeystat[:])
  copy(privkey[:32],kdfresult[:])
  var publicblob []byte
  publicblob = sshpubkey(pubkeystat)
  privblob := sshprivkey(pubkeystat,privkey)
  privblobstring := b64.StdEncoding.EncodeToString(privblob)
  //fmt.Println(privblobstring)
  publicblobstring := b64.StdEncoding.EncodeToString(publicblob)
  //fmt.Println(publicblobstring)
 namePtr := flag.String("out", "id_new", "destination filename")
 flag.Parse()
  f, err := os.Create(*namePtr)
  check(err)
  f.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
  f.WriteString(privblobstring+"\n")
  f.WriteString("-----END OPENSSH PRIVATE KEY-----\n")
  _ =f.Close
  pubf,err := os.Create(*namePtr+".pub")
  check(err)
  pubf.WriteString("ssh-ed25519 "+publicblobstring+ " root@porn\n")
  _=pubf.Close
}

func lenvalue (content []byte) (lengthencoded []byte){
  result := make([]byte, 4)
  binary.BigEndian.PutUint32(result,uint32(len(content)))
  lengthencoded = append(result[:],content[:]...)
  return lengthencoded

}
func sshpubkey(pubkey [PublicKeySize]byte) (sshpubkeyblob []byte) {
  sshpubkeyblob=lenvalue([]byte("ssh-ed25519"))
  sshpubkeyblob = append(sshpubkeyblob[:],lenvalue(pubkey[:])...)
  return sshpubkeyblob
}
func sshprivkey(pubkey [PublicKeySize]byte, privkey [PrivateKeySize]byte)(bytekey []byte) {
  // need to null terminate by myself
  start :=[]byte("openssh-key-v1\x00")
  //KDFs and stuff
  final :=append(start[:],lenvalue([]byte("none"))...)
  final = append(final[:],lenvalue([]byte("none"))...)
  // I care too fucking much to bother explaining these values i.e. don't know where they are coming from
  final = append(final[:],[]byte("\x00\x00\x00\x00")...)
  // This value left out to account for length null in previous byte array
  //final = append(final[:],[]byte("\xd1\xck\xbu\xtt"))
  final = append(final[:],[]byte("\x00\x00\x00\x01")...)
  final = append(final[:],[]byte("\x00\x00\x00\x33")...)
  final = append(final[:],lenvalue([]byte("ssh-ed25519"))...)
  final = append(final[:],[]byte("\x00\x00\x00\x20")...)
  final = append(final[:],pubkey[:]...)

  // some outer wrapping it is the encoding of private key
  final = append(final[:],[]byte("\x00\x00\x00\x90")...)
  // Found these numbers a7 33 93 e2 a7 33 93 e2
  // Lets add them twice for good measure
  final = append(final[:],[]byte("\xa7\x33\x93\xe2")...)
  final = append(final[:],[]byte("\xa7\x33\x93\xe2")...)
  // This shit again
  final = append(final[:],lenvalue([]byte("ssh-ed25519"))...)
  final = append(final[:],lenvalue(pubkey[:])...)
  // Finally, the only thing that was really needed
  final = append(final[:],lenvalue(privkey[:])...)
  // The original key comment
  final = append(final[:],lenvalue([]byte("root@porn"))...)
  // some counting to please the $deities
  final = append(final[:],[]byte("\x01\x02\x03\x04")...)
  return final
}
