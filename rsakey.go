package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path"
)

// func test() {
// 	//rsa 密钥文件产生
// 	GenRsaKey(1024)
// 	p, r, _ := ReadRsaFile("")
// 	fmt.Println("p:", string(p))
// 	fmt.Println("r:", string(r))
// }

//读取key文件
func LoadRSAFromPem(dir string,forceCreate... bool) (publicKey []byte, privateKey []byte, err error) {
    if len(forceCreate)>0 && forceCreate[0] && ( !fileIsExist(path.Join(dir, "public.pem")) ||  !fileIsExist(path.Join(dir, "private.pem"))) {
	  //RSA 密钥不存在，自动创建
	  GenRsaKey("keys", 1024)
	}

	publicKey, err = ioutil.ReadFile(path.Join(dir, "public.pem"))
    privateKey, err = ioutil.ReadFile(path.Join(dir, "private.pem"))
  
	return
}

//生成RSA公钥和私钥文件
func GenRsaKey(dir string, bits int) error {
	os.MkdirAll(dir, 0644)
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	file, err := os.Create(path.Join(dir, "private.pem"))
	if err != nil {
		return err
	}
	defer  file.Close() 
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	file, err = os.Create(path.Join(dir, "public.pem"))
	if err != nil {
		return err
	}
	defer  file.Close() 
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

//加密：采用sha1算法加密后转base64格式
func RsaEncryptWithSha1Base64(originalData string, publicKey []byte) (string, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return "public rsaKey error", nil
	}
	pubKey, _ := x509.ParsePKIXPublicKey(block.Bytes)
	encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey.(*rsa.PublicKey), []byte(originalData))
	return base64.StdEncoding.EncodeToString(encryptedData), err
}

//解密：对采用sha1算法加密后转base64格式的数据进行解密（私钥PKCS1格式）
func RsaDecryptWithSha1Base64(encryptedData string, privateKey []byte) (string, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return "private  rsaKey error", nil
	}

	encryptedDecodeBytes, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}
	//key, _ := base64.StdEncoding.DecodeString(privateKey)
	
	prvKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	originalData, err := rsa.DecryptPKCS1v15(rand.Reader, prvKey, encryptedDecodeBytes)
	// originalData, err := rsa.De(rand.Reader, prvKey, encryptedDecodeBytes)
	return string(originalData), err
}


func fileIsExist(path string) bool {
	_, err := os.Stat(path)
	return err == nil || os.IsExist(err)
}
