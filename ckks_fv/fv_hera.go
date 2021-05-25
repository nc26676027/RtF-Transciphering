package ckks_fv

import (
	"encoding/binary"
	"math/bits"

	"golang.org/x/crypto/blake2b"
)

type MFVHera interface {
	Init(nonces [][]byte)
	Crypt() []*Ciphertext
	KeySchedule(kCt []*Ciphertext)
	EncKey(key []uint64) (res []*Ciphertext)
}

type mfvHera struct {
	numRound int
	slots    int

	params         *Parameters
	encoder        MFVEncoder
	encryptor      MFVEncryptor
	evaluator      MFVEvaluator
	noiseEstimator MFVNoiseEstimator

	stCt []*Ciphertext
	rcPt [][]*PlaintextMul
	rkCt [][]*Ciphertext
}

func NewMFVHera(numRound int, params *Parameters, encoder MFVEncoder, encryptor MFVEncryptor, evaluator MFVEvaluator, noiseEstimator MFVNoiseEstimator) MFVHera {
	hera := new(mfvHera)

	hera.numRound = numRound
	hera.slots = params.FVSlots()

	hera.params = params
	hera.encoder = encoder
	hera.encryptor = encryptor
	hera.evaluator = evaluator
	hera.noiseEstimator = noiseEstimator

	hera.stCt = make([]*Ciphertext, 16)
	hera.rcPt = make([][]*PlaintextMul, numRound+1)

	for r := 0; r <= numRound; r++ {
		hera.rcPt[r] = make([]*PlaintextMul, 16)
		for st := 0; st < 16; st++ {
			hera.rcPt[r][st] = NewPlaintextMul(params)
		}
	}

	hera.rkCt = make([][]*Ciphertext, numRound+1)
	for r := 0; r <= numRound; r++ {
		hera.rkCt[r] = make([]*Ciphertext, 16)
	}

	// Precompute Initial States
	state := make([]uint64, hera.slots)
	stPT := NewPlaintextFV(params)

	for i := 0; i < 16; i++ {
		for j := 0; j < hera.slots; j++ {
			state[j] = uint64(i + 1) // ic = 1, ..., 16
		}
		encoder.EncodeUintSmall(state, stPT)
		hera.stCt[i] = encryptor.EncryptNew(stPT)
	}

	return hera
}

// Precompute Round Constants
func (hera *mfvHera) Init(nonce [][]byte) {
	var err error

	slots := hera.slots
	nr := hera.numRound
	xof := make([]blake2b.XOF, slots)

	bsize := (bits.Len64(hera.params.T()-2) + 7) / 8

	for i := 0; i < slots; i++ {
		if xof[i], err = blake2b.NewXOF(uint32(bsize*(nr+1)*16), nonce[i]); err != nil {
			panic("blake2b error")
		}
	}

	bufferN := make([]byte, bsize)
	intBuffer := make([]byte, 8)
	rc := make([]uint64, slots)

	for r := 0; r <= nr; r++ {
		for st := 0; st < 16; st++ {
			for slot := 0; slot < slots; slot++ {
				xof[slot].Read(bufferN)
				for c := 0; c < bsize; c++ {
					intBuffer[c] = bufferN[c]
				}
				rc[slot] = binary.LittleEndian.Uint64(intBuffer) + 1
			}
			hera.encoder.EncodeUintMulSmall(rc, hera.rcPt[r][st])
		}
	}
}

func (hera *mfvHera) KeySchedule(kCt []*Ciphertext) {
	for r := 0; r < hera.numRound+1; r++ {
		for st := 0; st < 16; st++ {
			hera.rkCt[r][st] = hera.evaluator.MulNew(kCt[st], hera.rcPt[r][st])
		}
	}
}

func (hera *mfvHera) Crypt() []*Ciphertext {
	// hera.keySchedule(kCt)
	hera.addRoundKey(0, false)

	for r := 1; r < hera.numRound; r++ {
		hera.linLayer()
		hera.cube()
		hera.addRoundKey(r, false)
	}
	hera.linLayer()
	hera.cube()
	hera.linLayer()
	hera.addRoundKey(hera.numRound, true)
	return hera.stCt
}

func (hera *mfvHera) addRoundKey(round int, reduce bool) {
	ev := hera.evaluator

	for st := 0; st < 16; st++ {
		if reduce {
			ev.Add(hera.stCt[st], hera.rkCt[round][st], hera.stCt[st])
		} else {
			ev.AddNoMod(hera.stCt[st], hera.rkCt[round][st], hera.stCt[st])
		}
	}
}

func (hera *mfvHera) linLayer() {
	ev := hera.evaluator

	for col := 0; col < 4; col++ {
		sum := ev.AddNoModNew(hera.stCt[col], hera.stCt[col+4])
		ev.AddNoMod(sum, hera.stCt[col+8], sum)
		ev.AddNoMod(sum, hera.stCt[col+12], sum)

		y0 := ev.AddNoModNew(sum, hera.stCt[col])
		ev.AddNoMod(y0, hera.stCt[col+4], y0)
		ev.AddNoMod(y0, hera.stCt[col+4], y0)

		y1 := ev.AddNoModNew(sum, hera.stCt[col+4])
		ev.AddNoMod(y1, hera.stCt[col+8], y1)
		ev.AddNoMod(y1, hera.stCt[col+8], y1)

		y2 := ev.AddNoModNew(sum, hera.stCt[col+8])
		ev.AddNoMod(y2, hera.stCt[col+12], y2)
		ev.AddNoMod(y2, hera.stCt[col+12], y2)

		y3 := ev.AddNoModNew(sum, hera.stCt[col+12])
		ev.AddNoMod(y3, hera.stCt[col], y3)
		ev.AddNoMod(y3, hera.stCt[col], y3)

		ev.Reduce(y0, hera.stCt[col])
		ev.Reduce(y1, hera.stCt[col+4])
		ev.Reduce(y2, hera.stCt[col+8])
		ev.Reduce(y3, hera.stCt[col+12])
	}

	for row := 0; row < 4; row++ {
		sum := ev.AddNoModNew(hera.stCt[4*row], hera.stCt[4*row+1])
		ev.AddNoMod(sum, hera.stCt[4*row+2], sum)
		ev.AddNoMod(sum, hera.stCt[4*row+3], sum)

		y0 := ev.AddNoModNew(sum, hera.stCt[4*row])
		ev.AddNoMod(y0, hera.stCt[4*row+1], y0)
		ev.AddNoMod(y0, hera.stCt[4*row+1], y0)

		y1 := ev.AddNoModNew(sum, hera.stCt[4*row+1])
		ev.AddNoMod(y1, hera.stCt[4*row+2], y1)
		ev.AddNoMod(y1, hera.stCt[4*row+2], y1)

		y2 := ev.AddNoModNew(sum, hera.stCt[4*row+2])
		ev.AddNoMod(y2, hera.stCt[4*row+3], y2)
		ev.AddNoMod(y2, hera.stCt[4*row+3], y2)

		y3 := ev.AddNoModNew(sum, hera.stCt[4*row+3])
		ev.AddNoMod(y3, hera.stCt[4*row], y3)
		ev.AddNoMod(y3, hera.stCt[4*row], y3)

		ev.Reduce(y0, hera.stCt[4*row])
		ev.Reduce(y1, hera.stCt[4*row+1])
		ev.Reduce(y2, hera.stCt[4*row+2])
		ev.Reduce(y3, hera.stCt[4*row+3])
	}
}

func (hera *mfvHera) cube() {
	ev := hera.evaluator
	for st := 0; st < 16; st++ {
		x2 := ev.MulNew(hera.stCt[st], hera.stCt[st])
		y2 := ev.RelinearizeNew(x2)
		x3 := ev.MulNew(y2, hera.stCt[st])
		hera.stCt[st] = ev.RelinearizeNew(x3)
	}
}

func (hera *mfvHera) EncKey(key []uint64) (res []*Ciphertext) {
	slots := hera.slots
	res = make([]*Ciphertext, 16)

	for i := 0; i < 16; i++ {
		dupKey := make([]uint64, slots)
		for j := 0; j < slots; j++ {
			dupKey[j] = key[i]
		}

		keyPt := NewPlaintextFV(hera.params)
		hera.encoder.EncodeUintSmall(dupKey, keyPt)
		res[i] = hera.encryptor.EncryptNew(keyPt)
	}
	return
}
