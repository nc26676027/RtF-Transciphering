package main

import (
	"encoding/binary"
	"fmt"
	"math/bits"

	"github.com/ldsec/lattigo/v2/ckks_fv"
	"golang.org/x/crypto/blake2b"
)

func testHera() {
	params := ckks_fv.DefaultFVParams[8]
	slots := params.FVSlots()

	nonces := make([][]byte, slots)

	for i := 0; i < slots; i++ {
		nonces[i] = make([]byte, 64)
	}

	key := make([]uint64, 16)
	for i := 0; i < 16; i++ {
		key[i] = uint64(i + 16)
	}

	keystream := plainHera(4, nonces[0], key, params.T())

	hera := ckks_fv.NewHEra(params)
	hera.Init(nonces)

	heKey := hera.EncKey(key)
	stCt := hera.Crypt(heKey)

	check := true
	for i := 0; i < 16; i++ {
		decrypted := hera.Decryptor.DecryptNew(stCt[i])
		decoded := hera.Encoder.DecodeUintNew(decrypted)

		fmt.Printf("%v (== %v)\n", decoded[0], keystream[i])

		if decoded[0] != keystream[i] {
			check = false
		}
		// fmt.Printf("%v\n", decrypted.Element.Value()[0])
	}

	fmt.Printf("Hera correct ? %v\n", check)
}

func plainHera(roundNum int, nonce []byte, key []uint64, t uint64) (state []uint64) {
	nr := roundNum
	bsize := (bits.Len64(t-2) + 7) / 8
	xof, _ := blake2b.NewXOF(uint32(bsize*(nr+1)*16), nonce)
	state = make([]uint64, 16)

	bufferN := make([]byte, bsize)
	intBuffer := make([]byte, 8)
	rks := make([][]uint64, nr+1)

	for r := 0; r <= nr; r++ {
		rks[r] = make([]uint64, 16)
		for st := 0; st < 16; st++ {
			xof.Read(bufferN)
			for c := 0; c < bsize; c++ {
				intBuffer[c] = bufferN[c]
			}
			rks[r][st] = (binary.LittleEndian.Uint64(intBuffer) + 1) * key[st] % t
		}
	}

	for i := 0; i < 16; i++ {
		state[i] = uint64(i + 1)
	}

	// round0
	for st := 0; st < 16; st++ {
		state[st] = (state[st] + rks[0][st]) % t
	}

	for r := 1; r < roundNum; r++ {
		for col := 0; col < 4; col++ {
			y0 := 2*state[col] + 3*state[col+4] + 1*state[col+8] + 1*state[col+12]
			y1 := 2*state[col+4] + 3*state[col+8] + 1*state[col+12] + 1*state[col]
			y2 := 2*state[col+8] + 3*state[col+12] + 1*state[col] + 1*state[col+4]
			y3 := 2*state[col+12] + 3*state[col] + 1*state[col+4] + 1*state[col+8]

			state[col] = y0 % t
			state[col+4] = y1 % t
			state[col+8] = y2 % t
			state[col+12] = y3 % t
		}

		for row := 0; row < 4; row++ {
			y0 := 2*state[4*row] + 3*state[4*row+1] + 1*state[4*row+2] + 1*state[4*row+3]
			y1 := 2*state[4*row+1] + 3*state[4*row+2] + 1*state[4*row+3] + 1*state[4*row]
			y2 := 2*state[4*row+2] + 3*state[4*row+3] + 1*state[4*row] + 1*state[4*row+1]
			y3 := 2*state[4*row+3] + 3*state[4*row] + 1*state[4*row+1] + 1*state[4*row+2]

			state[4*row] = y0 % t
			state[4*row+1] = y1 % t
			state[4*row+2] = y2 % t
			state[4*row+3] = y3 % t
		}

		for st := 0; st < 16; st++ {
			state[st] = (state[st] * state[st] % t) * state[st] % t
		}

		for st := 0; st < 16; st++ {
			state[st] = (state[st] + rks[r][st]) % t
		}
	}
	for col := 0; col < 4; col++ {
		y0 := 2*state[col] + 3*state[col+4] + 1*state[col+8] + 1*state[col+12]
		y1 := 2*state[col+4] + 3*state[col+8] + 1*state[col+12] + 1*state[col]
		y2 := 2*state[col+8] + 3*state[col+12] + 1*state[col] + 1*state[col+4]
		y3 := 2*state[col+12] + 3*state[col] + 1*state[col+4] + 1*state[col+8]

		state[col] = y0 % t
		state[col+4] = y1 % t
		state[col+8] = y2 % t
		state[col+12] = y3 % t
	}

	for row := 0; row < 4; row++ {
		y0 := 2*state[4*row] + 3*state[4*row+1] + 1*state[4*row+2] + 1*state[4*row+3]
		y1 := 2*state[4*row+1] + 3*state[4*row+2] + 1*state[4*row+3] + 1*state[4*row]
		y2 := 2*state[4*row+2] + 3*state[4*row+3] + 1*state[4*row] + 1*state[4*row+1]
		y3 := 2*state[4*row+3] + 3*state[4*row] + 1*state[4*row+1] + 1*state[4*row+2]

		state[4*row] = y0 % t
		state[4*row+1] = y1 % t
		state[4*row+2] = y2 % t
		state[4*row+3] = y3 % t
	}

	for st := 0; st < 16; st++ {
		state[st] = (state[st] * state[st] % t) * state[st] % t
	}

	for col := 0; col < 4; col++ {
		y0 := 2*state[col] + 3*state[col+4] + 1*state[col+8] + 1*state[col+12]
		y1 := 2*state[col+4] + 3*state[col+8] + 1*state[col+12] + 1*state[col]
		y2 := 2*state[col+8] + 3*state[col+12] + 1*state[col] + 1*state[col+4]
		y3 := 2*state[col+12] + 3*state[col] + 1*state[col+4] + 1*state[col+8]

		state[col] = y0 % t
		state[col+4] = y1 % t
		state[col+8] = y2 % t
		state[col+12] = y3 % t
	}

	for row := 0; row < 4; row++ {
		y0 := 2*state[4*row] + 3*state[4*row+1] + 1*state[4*row+2] + 1*state[4*row+3]
		y1 := 2*state[4*row+1] + 3*state[4*row+2] + 1*state[4*row+3] + 1*state[4*row]
		y2 := 2*state[4*row+2] + 3*state[4*row+3] + 1*state[4*row] + 1*state[4*row+1]
		y3 := 2*state[4*row+3] + 3*state[4*row] + 1*state[4*row+1] + 1*state[4*row+2]

		state[4*row] = y0 % t
		state[4*row+1] = y1 % t
		state[4*row+2] = y2 % t
		state[4*row+3] = y3 % t
	}

	for st := 0; st < 16; st++ {
		state[st] = (state[st] + rks[roundNum][st]) % t
	}
	return
}
