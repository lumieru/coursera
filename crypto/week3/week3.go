package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
)

const (
	BUFFER_BLOCKS     = 1024
	BLOCK_SIZE        = 1024
	HASH_SIZE         = sha256.Size
	HASHED_BLOCK_SIZE = BLOCK_SIZE + HASH_SIZE

	BUFFER_SIZE = BUFFER_BLOCKS * BLOCK_SIZE
)

var (
	inputFileName  = flag.String("i", "", "Specify the input file name.")
	outputFileName = flag.String("o", "", "Specify the output file name.")
	verifyFlag     = flag.String("v", "", "Hash0 value in hex")
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

	defer desFile.Close()

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
	desBuff := make([]byte, (bufferSize-blockSize)/BLOCK_SIZE*(BLOCK_SIZE+HASH_SIZE)+blockSize)
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
		hashValue = processBlocks(dataBuff, &desBuff, hashValue, blockSize)
		blockSize = BLOCK_SIZE
		bufferSize = BUFFER_SIZE

		srcLen -= (int64)(readedBytes)

		//write to dist file
		_, err = desFile.Seek((srcLen/BLOCK_SIZE)*(BLOCK_SIZE+HASH_SIZE), 0)
		//	log.Printf("Seek pos:%d, desBuff len:%d\ndes Buff:%v\n", (srcLen/BLOCK_SIZE)*(BLOCK_SIZE+HASH_SIZE),
		//	len(desBuff), desBuff)
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

func DecodeAndVerify(inputFileName, outputFileName string, hashValue *[HASH_SIZE]byte) error {
	file, err := os.Open(inputFileName)
	if err != nil {
		return fmt.Errorf("Open input file %s failed with:%v\n", inputFileName, err)
	}

	defer file.Close()

	desFile, err := os.Create(outputFileName)
	if err != nil {
		return fmt.Errorf("Create output file %s failed with: %v\n", outputFileName, err)
	}

	defer desFile.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("Get file state failed with: %v\n", err)
	}

	srcLen := fileInfo.Size()
	srcBlocks := int64(math.Ceil(float64(srcLen) / HASHED_BLOCK_SIZE))

	var bufferBlocks int64 = BUFFER_BLOCKS
	if bufferBlocks > srcBlocks {
		bufferBlocks = srcBlocks
	}

	srcBuff := make([]byte, HASHED_BLOCK_SIZE*bufferBlocks)
	desBuff := make([]byte, BLOCK_SIZE*bufferBlocks)

	var blockIndex int = 0
	for {
		readCount, err := file.Read(srcBuff)
		if err != nil {
			if err == io.EOF && readCount == 0 {
				// read finished
				return nil
			} else {
				return fmt.Errorf("Read from input file failed with: %v\n", err)
			}
		} else if readCount < len(srcBuff) {
			if srcLen >= int64(len(srcBuff)) {
				return fmt.Errorf("Not enough bytes read from file: %d < %d\n", readCount, len(srcBuff))
			} else if int64(readCount) == srcLen {
				srcBuff = srcBuff[:readCount]
			} else {
				return fmt.Errorf("Not enough bytes read from file: %d < %d\n", readCount, srcLen)
			}
		}

		srcLen -= int64(readCount)
		err = verifyBlocks(srcBuff, &desBuff, hashValue, &blockIndex)
		if err != nil {
			return err
		}

		writeCount, err := desFile.Write(desBuff)
		if err != nil || writeCount != len(desBuff) {
			return fmt.Errorf("Write to dst file failed with: %v. Or written bytes are not enough: %d < %d\n", err, writeCount, len(desBuff))
		}
	}
}

func verifyBlocks(srcBuff []byte, desBuff *[]byte, hashValue *[HASH_SIZE]byte, blockIndex *int) error {
	remainedSize := len(srcBuff)
	i := 0
	j := 0
	var verifyBlockSize int
	var lastBlock bool
	for remainedSize > 0 {
		if remainedSize >= HASHED_BLOCK_SIZE {
			verifyBlockSize = HASHED_BLOCK_SIZE
			lastBlock = false
		} else {
			verifyBlockSize = remainedSize
			lastBlock = true
		}

		if sha256.Sum256(srcBuff[i:i+verifyBlockSize]) == *hashValue {
			if lastBlock {
				copy((*desBuff)[j:j+verifyBlockSize], srcBuff[i:i+verifyBlockSize])
				j += verifyBlockSize
			} else {
				copy((*desBuff)[j:j+BLOCK_SIZE], srcBuff[i:i+BLOCK_SIZE])
				copy((*hashValue)[:], srcBuff[i+BLOCK_SIZE:i+HASHED_BLOCK_SIZE])
				j += BLOCK_SIZE
			}

			*blockIndex++
			remainedSize -= verifyBlockSize
		} else {
			return fmt.Errorf("Verify failed at block index %d\n", *blockIndex)
		}

		i += HASHED_BLOCK_SIZE
	}

	*desBuff = (*desBuff)[:j]

	return nil
}

func processBlocks(srcBuff []byte, desBuff *[]byte, hashValue []byte, blockSize int64) []byte {
	//	log.Print(srcBuff, desBuff, hashValue, blockSize)
	//	log.Print("len srcBuff=", len(srcBuff), "len desBuff=", len(desBuff))
	srcLen := (int64)(len(srcBuff))
	//	log.Print("srcLen=",srcLen)
	desOffset := (srcLen - blockSize) / BLOCK_SIZE * (BLOCK_SIZE + HASH_SIZE)
	//	log.Print("desOffset=",desOffset)
	if hashValue == nil {
		*desBuff = (*desBuff)[:desOffset+blockSize]
	} else {
		*desBuff = (*desBuff)[:desOffset+blockSize+HASH_SIZE]
	}
	for i := srcLen - blockSize; i >= 0; i -= BLOCK_SIZE {
		//		log.Print("i=",i,",desOffset=",desOffset)
		copy((*desBuff)[desOffset:desOffset+blockSize], srcBuff[i:i+blockSize])
		if hashValue != nil {
			copy((*desBuff)[desOffset+blockSize:desOffset+blockSize+HASH_SIZE], hashValue)
			res := sha256.Sum256((*desBuff)[desOffset : desOffset+blockSize+HASH_SIZE])
			hashValue = res[:]
			//			log.Print("desBuff=", desBuff[desOffset:desOffset+blockSize+HASH_SIZE], "len=", len(desBuff[desOffset:desOffset+blockSize+HASH_SIZE]))
			//			log.Print("hashValue=",hashValue)
		} else {
			res := sha256.Sum256((*desBuff)[desOffset : desOffset+blockSize])
			hashValue = res[:]
			//			log.Print("desBuff=", desBuff[desOffset:desOffset+blockSize], "len=", len(desBuff[desOffset:desOffset+blockSize]))
			//			log.Print("hashValue=",hashValue)
		}

		desOffset -= (BLOCK_SIZE + HASH_SIZE)
		blockSize = BLOCK_SIZE
	}

	return hashValue
}

func main() {
	flag.Parse()

	if *inputFileName == "" || *outputFileName == "" {
		fmt.Printf("%s <-i input file name> <-o output file name> [-v hash value]\n", os.Args[0])
		flag.PrintDefaults()
		return
	}

	bVerify := false

	for _, v := range os.Args {
		if v == "-v" {
			bVerify = true
		}
	}

	var hashValue0 [HASH_SIZE]byte

	if bVerify {
		if *verifyFlag != "" {
			hexValue, err := hex.DecodeString(*verifyFlag)
			if err != nil {
				fmt.Printf("Decodex hex string %s failed with: %v\n", *verifyFlag, err)
				return
			} else if len(hexValue) != HASH_SIZE {
				fmt.Printf("The length of hash value is not %d\n", HASH_SIZE)
				return
			}

			copy(hashValue0[:], hexValue)
			bVerify = true
		} else {
			fmt.Print("Hash value can not be empty.\n")
			return
		}
	}

	if bVerify {
		err := DecodeAndVerify(*inputFileName, *outputFileName, &hashValue0)
		if err != nil {
			log.Print(err)
		} else {
			log.Print("Verify and decode succeeded.\n")
		}
	} else {
		hashValue, err := EncodeAndHash(*inputFileName, *outputFileName)
		if err != nil {
			log.Print(err)
		} else {
			log.Print(hex.EncodeToString(hashValue))
		}
	}
}
