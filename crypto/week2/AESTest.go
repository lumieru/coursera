package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"log"
)

const (
	TYPE_CBC int = iota
	TYPE_CTR
)

type AESData struct {
	message    []byte
	ciphertext []byte
	key        []byte
	mode       int
}

var datas = [...]AESData{
	{[]byte("Basic CBC mode encryption needs padding."), []byte("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"), []byte("140b41b22a29beb4061bda66b6747e14"), TYPE_CBC},
	{[]byte("Our implementation uses rand. IV"), []byte("5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"), []byte("140b41b22a29beb4061bda66b6747e14"), TYPE_CBC},
	{[]byte("CTR mode lets you build a stream cipher from a block cipher."), []byte("69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"), []byte("36f18357be4dbd77f050515c73fcf9f2"), TYPE_CTR},
	{[]byte("Always avoid the two time pad!"), []byte("770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"), []byte("36f18357be4dbd77f050515c73fcf9f2"), TYPE_CTR},
}

func Encrypt() {
	iv := make([]byte, 16)
	for i := 0; i < len(datas); i++ {
		binKey := make([]byte, hex.DecodedLen(len(datas[i].key)))
		_, err := hex.Decode(binKey, datas[i].key)
		if err != nil {
			log.Printf("Decode hex key failed:%s\n", err.Error())
			return
		}
		aesCiper, err := aes.NewCipher(binKey)
		if err != nil {
			log.Printf("Create aes cipher failed:%s\n", err.Error())
			return
		}

		_, err = rand.Read(iv)
		if err != nil {
			log.Printf("Create iv failed:%s\n", err.Error())
			return
		}

		var dst []byte
		if datas[i].mode == TYPE_CBC {
			enc := NewMyCBCEncrypter(aesCiper, iv)
			dst = make([]byte, enc.EncryptedSize(len(datas[i].message)))
			enc.CryptBlocks(&dst, datas[i].message)
		} else {
			enc := NewMyCTR(aesCiper, iv)
			dst = make([]byte, enc.EncryptedSize(len(datas[i].message)))
			enc.XORKeyStream(&dst, datas[i].message, true)
		}

		log.Printf("src: %s => Dst:%x\n", datas[i].message, dst)
	}
}

func Decrypt() {
	iv := make([]byte, 16)
	for i := 0; i < len(datas); i++ {
		binKey := make([]byte, hex.DecodedLen(len(datas[i].key)))
		_, err := hex.Decode(binKey, datas[i].key)
		if err != nil {
			log.Printf("Decode hex key failed:%s\n", err.Error())
			return
		}
		aesCiper, err := aes.NewCipher(binKey)
		if err != nil {
			log.Printf("Create aes cipher failed:%s\n", err.Error())
			return
		}

		_, err = rand.Read(iv)
		if err != nil {
			log.Printf("Create iv failed:%s\n", err.Error())
			return
		}

		binBuffer := make([]byte, hex.DecodedLen(len(datas[i].ciphertext)))
		_, err = hex.Decode(binBuffer, datas[i].ciphertext)
		if err != nil {
			log.Printf("Decode hex failed:%s\n", err.Error())
			return
		}
		dst := make([]byte, len(binBuffer))

		if datas[i].mode == TYPE_CBC {
			enc := NewMyCBCDecrypter(aesCiper, iv)
			enc.CryptBlocks(&dst, binBuffer)
		} else {
			enc := NewMyCTR(aesCiper, iv)
			enc.XORKeyStream(&dst, binBuffer, false)
		}

		log.Printf("src: %s => Dst:%s\n", datas[i].message, dst)
	}
}

func main() {
	//Encrypt()
	Decrypt()
}
