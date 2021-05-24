package ckks_fv

import (
	"encoding/binary"
	"fmt"
	"math/bits"

	"golang.org/x/crypto/blake2b"
)

type HEra struct {
	params   *Parameters
	numRound int

	Encoder   MFVEncoder
	Encryptor MFVEncryptor
	Decryptor MFVDecryptor
	Evaluator MFVEvaluator

	noiseEstimator MFVNoiseEstimator

	stCt []*Ciphertext
	rcPt [][]*PlaintextMul
	rkCt [][]*Ciphertext
}

func NewHEra(params *Parameters) (hera *HEra) {
	kgen := NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()

	hera = new(HEra)

	hera.params = params.Copy()
	hera.numRound = 4

	hera.Encoder = NewMFVEncoder(params)
	hera.Encryptor = NewMFVEncryptorFromPk(params, pk)
	hera.Decryptor = NewMFVDecryptor(params, sk)
	hera.noiseEstimator = NewMFVNoiseEstimator(params, sk)
	pDcds := hera.Encoder.GenSlotToCoeffMatFV()
	rotations := kgen.GenRotationIndexesForSlotsToCoeffsMat(pDcds)

	rotkeys := kgen.GenRotationKeysForRotations(rotations, true, sk)
	rlk := kgen.GenRelinearizationKey(sk)

	hera.Evaluator = NewMFVEvaluator(params, EvaluationKey{Rlk: rlk, Rtks: rotkeys}, pDcds)

	hera.stCt = make([]*Ciphertext, 16)
	hera.stCt = make([]*Ciphertext, 16)
	hera.rcPt = make([][]*PlaintextMul, hera.numRound+1)
	for r := 0; r < hera.numRound+1; r++ {
		hera.rcPt[r] = make([]*PlaintextMul, 16)
		for st := 0; st < 16; st++ {
			hera.rcPt[r][st] = NewPlaintextMul(params)
		}
	}

	hera.rkCt = make([][]*Ciphertext, hera.numRound+1)
	for r := 0; r < hera.numRound+1; r++ {
		hera.rkCt[r] = make([]*Ciphertext, 16)
	}
	hera.newHEra()
	return
}

// Precompute Initial State
func (hera *HEra) newHEra() {
	slots := hera.params.FVSlots()

	st := make([]uint64, slots)
	stPT := NewPlaintextFV(hera.params)

	for i := 0; i < 16; i++ {
		for j := 0; j < slots; j++ {
			st[j] = uint64(i + 1) // ic = 1, ..., 16
		}
		hera.Encoder.EncodeUint(st, stPT)
		hera.stCt[i] = hera.Encryptor.EncryptNew(stPT)
	}
}

// Precompute Round Constants
func (hera *HEra) Init(nonce [][]byte) {
	var err error

	slots := hera.params.FVSlots()
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
			hera.Encoder.EncodeUintMul(rc, hera.rcPt[r][st])
		}
	}
}

func (hera *HEra) KeySchedule(kCt []*Ciphertext) {
	for r := 0; r < hera.numRound+1; r++ {
		for st := 0; st < 16; st++ {
			hera.rkCt[r][st] = hera.Evaluator.MulNew(kCt[st], hera.rcPt[r][st])
		}
	}
}

func (hera *HEra) Crypt(kCt []*Ciphertext) []*Ciphertext {
	hera.KeySchedule(kCt)
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
	fmt.Printf("Budget Left : %d\n", hera.noiseEstimator.InvariantNoiseBudget(hera.stCt[0]))
	return hera.stCt

	/*
		out := make([]*Ciphertext, 16)
		for i := 0; i < 16; i++ {
			out[i] = hera.Evaluator.SlotsToCoeffs(hera.stCt[i])
			fmt.Printf("Budget Left : %d\n", hera.noiseEstimator.InvariantNoiseBudget(out[i]))
		}
		return out
	*/
}

func (hera *HEra) addRoundKey(round int, reduce bool) {
	ev := hera.Evaluator

	for st := 0; st < 16; st++ {
		if reduce {
			ev.Add(hera.stCt[st], hera.rkCt[round][st], hera.stCt[st])
		} else {
			ev.AddNoMod(hera.stCt[st], hera.rkCt[round][st], hera.stCt[st])
		}
	}
}

func (hera *HEra) linLayer() {
	ev := hera.Evaluator

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

func (hera *HEra) cube() {
	ev := hera.Evaluator
	for st := 0; st < 16; st++ {
		x2 := ev.MulNew(hera.stCt[st], hera.stCt[st])
		y2 := ev.RelinearizeNew(x2)
		x3 := ev.MulNew(y2, hera.stCt[st])
		hera.stCt[st] = ev.RelinearizeNew(x3)
	}
}

func (hera *HEra) EncKey(key []uint64) (res []*Ciphertext) {
	slots := hera.params.FVSlots()
	res = make([]*Ciphertext, 16)

	for i := 0; i < 16; i++ {
		dupKey := make([]uint64, slots)
		for j := 0; j < slots; j++ {
			dupKey[j] = key[i]
		}

		keyPt := NewPlaintextFV(hera.params)
		hera.Encoder.EncodeUint(dupKey, keyPt)
		res[i] = hera.Encryptor.EncryptNew(keyPt)
	}
	return
}
