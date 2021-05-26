package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/ldsec/lattigo/v2/ckks_fv"
	"github.com/ldsec/lattigo/v2/utils"
	"golang.org/x/crypto/sha3"
)

func testHera() {
	params, _ := ckks_fv.RtFParams[2].Params()
	numRound := 5
	heraModDown := ckks_fv.HeraModDownParams80[2]
	stcModDown := ckks_fv.StcModDownParams80[2]
	_, _ = heraModDown, stcModDown

	fullCoeffs := true
	fullCoeffs = fullCoeffs && (params.LogN() == params.LogSlots()+1)
	if fullCoeffs {
		params.SetLogFVSlots(params.LogN())
	} else {
		params.SetLogFVSlots(params.LogSlots())
	}

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
		keystreams[i] = plainHera(numRound, nonces[i], key, params.T())
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

	hera := ckks_fv.NewMFVHera(numRound, params, fvEncoder, fvEncryptor, fvEvaluator, 4)
	heKey := hera.EncKey(key)
	fmt.Printf("===== Encrypt Start with %d Slots =====\n", slots)
	stCt := hera.CryptAutoModSwitch(nonces, heKey, fvNoiseEstimator)
	// stCt := hera.CryptNoModSwitch(nonces, heKey)
	// _ = fvNoiseEstimator
	for i := 0; i < 16; i++ {
		// ksSlot := fvEvaluator.SlotsToCoeffs(stCt[i], stcModDown)
		ksSlot := fvEvaluator.SlotsToCoeffsAutoModSwitch(stCt[i], fvNoiseEstimator)
		// ksSlot := fvEvaluator.SlotsToCoeffsNoModSwitch(stCt[i])
		fmt.Printf("Budget Remain : %d\n", fvNoiseEstimator.InvariantNoiseBudget(ksSlot))
		fvEvaluator.ModSwitchMany(ksSlot, ksSlot, ksSlot.Level())
		fmt.Printf("Budget Final : %d\n", fvNoiseEstimator.InvariantNoiseBudget(ksSlot))

		ksCt := fvDecryptor.DecryptNew(ksSlot)
		ksCoef := ckks_fv.NewPlaintextRingT(params)
		fvEncoder.DecodeRingT(ksCt, ksCoef)

		for j := 0; j < slots; j++ {
			br_j := utils.BitReverse64(uint64(j), uint64(params.LogN()))
			// fmt.Printf("%5v ", ksCoef.Element.Value()[0].Coeffs[0][br_j])

			if ksCoef.Element.Value()[0].Coeffs[0][br_j] != keystreams[j][i] {
				fmt.Printf("[-] Validity failed")
				os.Exit(0)
			}
		}
		/*
			fmt.Println("==")
			for j := 0; j < slots; j++ {
				fmt.Printf("%5v ", keystreams[j][i])
			}
			fmt.Print("\n\n\n")
		*/
	}
	fmt.Print("[+] Validity Ok\n\n")
}

func plainHera(roundNum int, nonce []byte, key []uint64, t uint64) (state []uint64) {
	nr := roundNum
	xof := sha3.NewShake256()
	xof.Write(nonce)
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
