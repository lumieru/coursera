package main

import (
	"crypto/cipher"
	"encoding/binary"
)

type MyCBCEncrypter struct {
	iv    []byte
	block cipher.Block
}

// BlockSize returns the mode's block size.
func (enc *MyCBCEncrypter) BlockSize() int {
	return enc.block.BlockSize()
}

func (enc *MyCBCEncrypter) EncryptedSize(srcLen int) int {
	// source len + iv len + padding len
	return srcLen + enc.BlockSize() + enc.BlockSize() - srcLen%enc.BlockSize()
}

// CryptBlocks encrypts or decrypts a number of blocks. The length of
// src must be a multiple of the block size. Dst and src may point to
// the same memory.
func (enc *MyCBCEncrypter) CryptBlocks(dst *[]byte, src []byte) {
	if len(*dst) < enc.EncryptedSize(len(src)) {
		panic("len(dst) < enc.EncryptedSize(len(src)")
	}

	//set iv to dst
	copy(*dst, enc.iv)

	blockSize := enc.BlockSize()
	srcLen := len(src)

	i := blockSize
	j := 0
	key := enc.iv
	tempBuff := make([]byte, blockSize)

	for {
		if srcLen-j >= blockSize {
			enc.block.Encrypt((*dst)[i:i+blockSize], xorSlice(tempBuff, src[j:j+blockSize], key))
		} else {
			//padding
			padded := make([]byte, blockSize)
			copy(padded, src[j:])
			remained := len(src[j:])
			paddingSize := blockSize - remained
			for k := 0; k < paddingSize; k++ {
				padded[remained+k] = (byte)(paddingSize)
			}

			enc.block.Encrypt((*dst)[i:i+blockSize], xorSlice(tempBuff, padded, key))
			*dst = (*dst)[:i+blockSize]
			break
		}

		key = (*dst)[i : i+blockSize]
		i += blockSize
		j += blockSize
	}
}

func NewMyCBCEncrypter(b cipher.Block, iv []byte) *MyCBCEncrypter {
	if len(iv) != b.BlockSize() {
		return nil
	}

	return &MyCBCEncrypter{
		iv:    iv,
		block: b,
	}
}

type MyCBCDecrypter struct {
	iv    []byte
	block cipher.Block
}

// BlockSize returns the mode's block size.
func (dec *MyCBCDecrypter) BlockSize() int {
	return dec.block.BlockSize()
}

// CryptBlocks encrypts or decrypts a number of blocks. The length of
// src must be a multiple of the block size. Dst and src may point to
// the same memory.
func (dec *MyCBCDecrypter) CryptBlocks(dst *[]byte, src []byte) {
	if len(*dst) < len(src) {
		panic("len(dst) < len(src)")
	}

	blockSize := dec.BlockSize()

	if len(src)%blockSize != 0 {
		panic("src must be a multiple of the block size.")
	}

	key := src[:blockSize]

	i := 0
	j := blockSize
	tempBuff := make([]byte, blockSize)

	for j < len(src) {
		dec.block.Decrypt(tempBuff, src[j:j+blockSize])

		xorSlice((*dst)[i:i+blockSize], tempBuff, key)

		key = src[j : j+blockSize]
		i += blockSize
		j += blockSize
	}

	//remove padding
	paddingSize := (int)((*dst)[i-1])
	*dst = (*dst)[:i-paddingSize]
}

func NewMyCBCDecrypter(b cipher.Block, iv []byte) *MyCBCDecrypter {
	if len(iv) != b.BlockSize() {
		return nil
	}

	return &MyCBCDecrypter{
		iv:    iv,
		block: b,
	}
}

type MyCTR struct {
	iv    []byte
	block cipher.Block
}

func (enc *MyCTR) EncryptedSize(srcLen int) int {
	// source len + iv len + padding len
	return srcLen + enc.block.BlockSize()
}

// XORKeyStream XORs each byte in the given slice with a byte from the
// cipher's key stream. Dst and src may point to the same memory.
// If len(dst) < len(src), XORKeyStream should panic. It is acceptable
// to pass a dst bigger than src, and in that case, XORKeyStream will
// only update dst[:len(src)] and will not touch the rest of dst.
func (ctr *MyCTR) XORKeyStream(dst *[]byte, src []byte, bEncrypt bool) {
	additionLen := 0
	if bEncrypt {
		additionLen += ctr.block.BlockSize()
	}
	if len(*dst) < len(src)+additionLen {
		panic("len(dst) < len(src) + additionLen")
	}

	blockSize := ctr.block.BlockSize()
	tempBuff := make([]byte, blockSize)
	key := make([]byte, blockSize)

	var j int
	var i int
	if bEncrypt {
		copy(*dst, ctr.iv)
		copy(key, ctr.iv)
		j = blockSize
		i = 0
	} else {
		copy(key, src[:blockSize])
		j = 0
		i = blockSize
	}

	last64BitKey := key[blockSize-8 : blockSize]
	var counter uint64 = binary.BigEndian.Uint64(last64BitKey)
	var blockLen int = blockSize

	for i < len(src) {
		binary.BigEndian.PutUint64(last64BitKey, counter)
		ctr.block.Encrypt(tempBuff, key)

		if i+blockSize <= len(src) {
			blockLen = blockSize
		} else {
			blockLen = len(src) - i
		}

		xorSlice((*dst)[j:j+blockLen], src[i:i+blockLen], tempBuff)
		i += blockLen
		j += blockLen
		counter++
	}

	*dst = (*dst)[:j]
}

func NewMyCTR(block cipher.Block, iv []byte) *MyCTR {
	if len(iv) != block.BlockSize() {
		return nil
	}

	return &MyCTR{
		iv:    iv,
		block: block,
	}
}

func xorSlice(dst, src, key []byte) []byte {
	for i := 0; i < len(src); i++ {
		dst[i] = src[i] ^ key[i]
	}

	return dst
}
