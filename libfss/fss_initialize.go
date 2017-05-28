package libfss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// Initialize functions for client and server
// You should initialize after each query on the database like in
// Private Information Retrieval (PIR)

// initialize client with this function
// numBits represents the input domain for the function, i.e. the number
// of bits to check
func ClientInitialize(numBits uint) *Fss {
	f := new(Fss)
	// numBits = 6
	f.NumBits = numBits
	// initPRFLen = 4 (@fss_util.go)
	f.PrfKeys = make([][]byte, initPRFLen)
	// Create fixed AES blocks
	f.FixedBlocks = make([]cipher.Block, initPRFLen)
	// 長度為4的迴圈
	for i := uint(0); i < initPRFLen; i++ {
		// 一維陣列，長度=16
		f.PrfKeys[i] = make([]byte, aes.BlockSize)
		// 隨機讀取16個數字，放入f.PrfKeys[i]
		rand.Read(f.PrfKeys[i])
		// 產生加密用的block
		block, err := aes.NewCipher(f.PrfKeys[i])
		if err != nil {
			panic(err.Error())
		}
		f.FixedBlocks[i] = block
	}
	// Check if int is 32 or 64 bit
	var x uint64 = 1 << 32
	if uint(x) == 0 {
		f.N = 32
	} else {
		f.N = 64
	}
	f.M = 4 // Default is 4. Only used in multiparty. To change this, you should change the size of the CW in multiparty keys. Read comments there.
	f.Temp = make([]byte, aes.BlockSize)
	f.Out = make([]byte, aes.BlockSize*initPRFLen)
	return f
}

// upon receiving query from server, initialize server with
// this function. The server, unlike the client
// receives prfKeys, so it doesn't need to pick random ones
func ServerInitialize(prfKeys [][]byte, numBits uint) *Fss {
	f := new(Fss)
	f.NumBits = numBits
	f.PrfKeys = make([][]byte, initPRFLen)
	f.FixedBlocks = make([]cipher.Block, initPRFLen)
	for i := range prfKeys {
		f.PrfKeys[i] = make([]byte, aes.BlockSize)
		copy(f.PrfKeys[i], prfKeys[i])
		block, err := aes.NewCipher(f.PrfKeys[i])
		if err != nil {
			panic(err.Error())
		}
		f.FixedBlocks[i] = block
	}
	// Check if int is 32 or 64 bit
	var x uint64 = 1 << 32
	if uint(x) == 0 {
		f.N = 32
	} else {
		f.N = 64
	}
	f.M = 4 // Again default = 4. Look at comments in ClientInitialize to understand this.
	f.Temp = make([]byte, aes.BlockSize)
	f.Out = make([]byte, aes.BlockSize*initPRFLen)

	return f
}
