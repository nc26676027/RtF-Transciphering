package main

import (
	"crypto/rand"
	"fmt"

	"github.com/ldsec/lattigo/v2/ckks_fv"
	"github.com/ldsec/lattigo/v2/utils"
	"golang.org/x/crypto/blake2b"
)

func testHera() {
	params := ckks_fv.DefaultFVParams[8]
	slots := params.FVSlots()

	nonces := make([][]byte, slots)
	for i := 0; i < slots; i++ {
		nonces[i] = make([]byte, 64)
		rand.Read(nonces[i])
	}

	key := make([]uint64, 16)
	for i := 0; i < 16; i++ {
		key[i] = uint64(i + 16)
	}

	keystreams := make([][]uint64, slots)
	for i := 0; i < slots; i++ {
		keystreams[i] = plainHera(4, nonces[i], key, params.T())
	}

	kgen := ckks_fv.NewKeyGenerator(params)

	sk, pk := kgen.GenKeyPair()

	fvEncoder := ckks_fv.NewMFVEncoder(params)
	fvEncryptor := ckks_fv.NewMFVEncryptorFromPk(params, pk)
	fvDecryptor := ckks_fv.NewMFVDecryptor(params, sk)

	pDcds := fvEncoder.GenSlotToCoeffMatFV()
	rotations := kgen.GenRotationIndexesForSlotsToCoeffsMat(pDcds)
	rotkeys := kgen.GenRotationKeysForRotations(rotations, true, sk)
	rlk := kgen.GenRelinearizationKey(sk)

	fvEvaluator := ckks_fv.NewMFVEvaluator(params, ckks_fv.EvaluationKey{Rlk: rlk, Rtks: rotkeys}, pDcds)
	fvNoiseEstimator := ckks_fv.NewMFVNoiseEstimator(params, sk)

	hera := ckks_fv.NewMFVHera(4, params, fvEncoder, fvEncryptor, fvEvaluator, fvNoiseEstimator)
	hera.Init(nonces)

	heKey := hera.EncKey(key)
	hera.KeySchedule(heKey)
	stCt := hera.Crypt()

	for i := 0; i < 16; i++ {
		ksSlot := fvEvaluator.SlotsToCoeffs(stCt[i])
		ksCt := fvDecryptor.DecryptNew(ksSlot)
		ksCoef := ckks_fv.NewPlaintextRingT(params)
		fvEncoder.DecodeRingT(ksCt, ksCoef)

		for j := 0; j < slots; j++ {
			br_j := utils.BitReverse64(uint64(j), uint64(params.LogN()))
			fmt.Printf("%5v ", ksCoef.Element.Value()[0].Coeffs[0][br_j])
		}
		fmt.Println("==")
		for j := 0; j < slots; j++ {
			fmt.Printf("%5v ", keystreams[j][i])
		}
		fmt.Print("\n\n")
	}
}

func plainHera(roundNum int, nonce []byte, key []uint64, t uint64) (state []uint64) {
	nr := roundNum
	xof, _ := blake2b.NewXOF(blake2b.OutputLengthUnknown, nonce)
	state = make([]uint64, 16)

	rks := make([][]uint64, nr+1)

	for r := 0; r <= nr; r++ {
		rks[r] = make([]uint64, 16)
		for st := 0; st < 16; st++ {
			rks[r][st] = ckks_fv.SampleZtx(xof, t) * key[st] % t
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
