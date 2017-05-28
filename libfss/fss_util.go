package libfss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
)

type Fss struct {
	// store keys used in fixedBlocks so that they can be sent to the server
	PrfKeys     [][]byte
	FixedBlocks []cipher.Block
	M           uint // used only in multiparty. It is default to 4. If you want to change this, you should also change the size of the CWs in the multiparty keys.
	N           uint
	NumBits     uint   // number of bits in domain
	Temp        []byte // temporary slices so that we only need to allocate memory at the beginning
	Out         []byte
}

const initPRFLen uint = 4

func randomCryptoInt() uint {
	b := make([]byte, 8)
	rand.Read(b)
	ans, _ := binary.Uvarint(b)
	return uint(ans)
}

// 0th position is the most significant bit
// True if bit is 1 and False if bit is 0
// N is the number of bits in uint
func getBit(n, pos, N uint) byte {
	// 1的低位(右邊)補(N - pos)個0
	// val = n轉二進制，與上面計算後的值，同位數都為1時為1，其他都為0
	val := (n & (1 << (N - pos)))
	if val > 0 {
		return 1
	} else {
		return 0
	}
	//5,59,64 return 0
	//5,60,64 return 0
	//5,61,64 return 0
	//5,62,64 return 1
	//5,63,64 return 0
	//5,64,64 return 1
}

// fixed key PRF (Matyas–Meyer–Oseas one way compression function)
// numBlocks represents the number
func prf(x []byte, aesBlocks []cipher.Block, numBlocks uint, temp, out []byte) {
	// If request blocks greater than actual needed blocks, grow output array
	// numBlocks = 3, initPRFLen = 4，所以基本上，下面這個判斷是不會進去
	if numBlocks > initPRFLen {
		out = make([]byte, numBlocks*aes.BlockSize)
	}
	for i := uint(0); i < numBlocks; i++ {
		// get AES_k[i](x)
		aesBlocks[i].Encrypt(temp, x)
		// get AES_k[i](x) ^ x
		for j := range temp {
			out[i*aes.BlockSize+uint(j)] = temp[j] ^ x[j]
		}
	}
}
