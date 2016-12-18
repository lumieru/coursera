package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/net/proxy"
	"log"
	"net/http"
	"os"
)

var (
	httpClient *http.Client
	socks5Flag = flag.String("s5", "", "Specify a socks5 proxy to be used, format: \"address:port\"")
	cipherText = flag.String("ct", "", "Cipher text to be decypted.")
)

// return true when the padding is valid
func isPaddingValid(cipherText string) bool {
	resp, err := httpClient.Get(fmt.Sprintf("http://crypto-class.appspot.com/po?er=%s", cipherText))
	if err != nil {
		log.Fatal(err)
		return false
	} else {
		defer resp.Body.Close()
		if resp.StatusCode == 404 {
			return true
		} else {
			return false
		}
	}
}

func setupHttpClient(socks5Address string) error {
	if socks5Address != "" {
		// create a socks5 dialer
		dialer, err := proxy.SOCKS5("tcp", socks5Address, nil, proxy.Direct)
		if err != nil {
			return fmt.Errorf("can't connect to the proxy: %v", err)
		}
		// setup a http client
		httpTransport := &http.Transport{}
		httpClient = &http.Client{Transport: httpTransport}
		// set our socks5 as the dialer
		httpTransport.Dial = dialer.Dial
	} else {
		httpClient = http.DefaultClient
	}

	return nil
}

func decryptUsingCBCPaddingOracle(twoCipherBlocks []byte, onePlainBlock []byte) error {
	tempBlocks := make([]byte, len(twoCipherBlocks))
	copy(tempBlocks, twoCipherBlocks)
	for i := 15; i >= 0; i-- {
		pad := byte(16 - i)
		for k := 15; k > i; k-- {
			tempBlocks[k] = twoCipherBlocks[k] ^ onePlainBlock[k] ^ pad
		}
		j := 0
		for ; j < 256; j++ {
			tempBlocks[i] = twoCipherBlocks[i] ^ byte(j) ^ pad
			if isPaddingValid(hex.EncodeToString(tempBlocks)) {
				onePlainBlock[i] = byte(j)
				break
			}
		}
		if j == 256 {
			return fmt.Errorf("Failed to decrypt byte in position %d", i)
		}
	}

	return nil
}

func decryptCipherText(cipherText []byte) ([]byte, error) {
	cipherBytes := make([]byte, hex.DecodedLen(len(cipherText)))
	_, err := hex.Decode(cipherBytes, cipherText)
	if err != nil {
		return nil, fmt.Errorf("hex decode failed with error: %v", err)
	}

	srcLen := len(cipherBytes)
	if srcLen%16 != 0 {
		return nil, fmt.Errorf("Invalid length of cipher text: %d", srcLen)
	}

	blocks := srcLen / 16
	dstBytes := make([]byte, (blocks-1)*16)
	for i := 1; i < blocks; i++ {
		if err = decryptUsingCBCPaddingOracle(cipherBytes[(i-1)*16:(i+1)*16], dstBytes[(i-1)*16:i*16]); err != nil {
			return nil, fmt.Errorf("Decrypt block at position %d failed:%v", i, err)
		}
	}

	return dstBytes, nil
}

func main() {
	flag.Parse()

	if *cipherText == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	err := setupHttpClient(*socks5Flag)
	if err != nil {
		log.Fatal(err)
	}

	plainText, err := decryptCipherText([]byte(*cipherText))
	if err != nil {
		log.Fatal(err)
	} else {
		log.Print(string(plainText))
	}
}
