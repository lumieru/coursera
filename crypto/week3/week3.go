package main

import (
	"os"
	"fmt"
	"crypto/sha256"
	"flag"
	"log"
	"encoding/hex"
)

const (
	BLOCK_SIZE = 1024
	BUFFER_SIZE = 1024 * BLOCK_SIZE
	HASH_SIZE = sha256.Size
)

var (
	inputFileName = flag.String("i", "", "Specify the input file name.")
	outputFileName = flag.String("o", "", "Specify the output file name.")
)

func EncodeAndHash(inputFileName, outputFileName string) ([]byte, error) {
	file, err := os.Open(inputFileName)
	if err != nil {
		return nil, fmt.Errorf("Open input file %s failed with:%v\n", inputFileName, err)
	}

	defer file.Close()

	desFile, err := os.Create(outputFileName)
	if err != nil {
		return nil, fmt.Errorf("Create output file %s failed with: %v\n", outputFileName, err)
	}

	defer  desFile.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("Get file state failed with: %v\n", err)
	}

	srcLen := fileInfo.Size()
	blockSize := srcLen % BLOCK_SIZE
	bufferSize := BUFFER_SIZE + blockSize
	if srcLen < bufferSize {
		bufferSize = srcLen
	}

	// move pointer to the end
	_, err = file.Seek(-bufferSize, 2)
	if err != nil {
		return nil, fmt.Errorf("Seek file failed with: %v\n", err)
	}
	dataBuff := make([]byte, bufferSize)
	desBuff := make([]byte, (bufferSize-blockSize)/BLOCK_SIZE * (BLOCK_SIZE+HASH_SIZE) + blockSize)
	var hashValue []byte = nil

	if blockSize == 0 {
		blockSize = BLOCK_SIZE
	}

	for {
		readedBytes, err := file.Read(dataBuff)
		if err != nil {
			return nil, fmt.Errorf("Read file failed with: %v\n", err)
		} else if readedBytes != len(dataBuff) {
			return nil, fmt.Errorf("Readed bytes is not enough: %d < %d\n", readedBytes, len(dataBuff))
		}
		//process dataBuff
		hashValue = processBlocks(dataBuff, desBuff, hashValue, blockSize)
		blockSize = BLOCK_SIZE
		bufferSize = BUFFER_SIZE

		srcLen -= (int64)(readedBytes)

		//write to dist file
		_, err = desFile.Seek((srcLen/BLOCK_SIZE)*(BLOCK_SIZE+HASH_SIZE), 0)
		if err != nil {
			return nil, fmt.Errorf("Seek dst file failed with: %v\n", err)
		}

		writedBytes, err := desFile.Write(desBuff)
		if err != nil || writedBytes < len(desBuff) {
			return nil, fmt.Errorf("Write to dst file failed with: %v. Or written bytes are not enough: %d < %d\n", err, writedBytes, len(desBuff))
		}

		//read next buffer
		if srcLen <= 0 {
			break
		} else if srcLen < bufferSize {
			bufferSize = srcLen
		}
		dataBuff = dataBuff[:bufferSize]

		_, err = file.Seek(-(int64)(readedBytes)-bufferSize, 1)
		if err != nil {
			return nil, fmt.Errorf("Seek file failed with: %v\n", err)
		}
	}

	return hashValue, nil
}

func DecodeAndVerify(inputFileName string, h0 []byte) error {
	return nil
}

func processBlocks(srcBuff, desBuff, hashValue []byte, blockSize int64) []byte {
//	log.Print(srcBuff, desBuff, hashValue, blockSize)
//	log.Print("len srcBuff=", len(srcBuff), "len desBuff=", len(desBuff))
	srcLen := (int64)(len(srcBuff))
//	log.Print("srcLen=",srcLen)
	desOffset := (srcLen-blockSize)/BLOCK_SIZE * (BLOCK_SIZE+HASH_SIZE)
//	log.Print("desOffset=",desOffset)
	if hashValue == nil {
		desBuff = desBuff[:desOffset+blockSize]
	} else {
		desBuff = desBuff[:desOffset+blockSize+HASH_SIZE]
	}
	for i:=srcLen-blockSize; i>=0; i-=BLOCK_SIZE {
//		log.Print("i=",i,",desOffset=",desOffset)
		copy(desBuff[desOffset:desOffset+blockSize], srcBuff[i:i+blockSize])
		if hashValue != nil {
			copy(desBuff[desOffset+blockSize:desOffset+blockSize+HASH_SIZE],hashValue)
			res := sha256.Sum256(desBuff[desOffset:desOffset+blockSize+HASH_SIZE])
			hashValue = res[:]
//			log.Print("desBuff=", desBuff[desOffset:desOffset+blockSize+HASH_SIZE], "len=", len(desBuff[desOffset:desOffset+blockSize+HASH_SIZE]))
//			log.Print("hashValue=",hashValue)
		} else {
			res := sha256.Sum256(desBuff[desOffset:desOffset+blockSize])
			hashValue = res[:]
//			log.Print("desBuff=", desBuff[desOffset:desOffset+blockSize], "len=", len(desBuff[desOffset:desOffset+blockSize]))
//			log.Print("hashValue=",hashValue)
		}

		desOffset -= (BLOCK_SIZE+HASH_SIZE)
		blockSize = BLOCK_SIZE
	}

	return hashValue
}

func main() {
	flag.Parse()

	if *inputFileName == "" || *outputFileName == "" {
		fmt.Printf("%s <-i input file name> <-o output file name>\n", os.Args[0])
		flag.PrintDefaults()
		return
	}

	hashValue, err := EncodeAndHash(*inputFileName, *outputFileName)
	if err != nil {
		log.Print(err)
	} else {
		log.Print(hex.EncodeToString(hashValue))
	}
}
