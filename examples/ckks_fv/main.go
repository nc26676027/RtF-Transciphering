package main

import (
	"crypto/rand"
	"fmt"
	"math"
	"os"

	"github.com/ldsec/lattigo/v2/ckks_fv"
	"github.com/ldsec/lattigo/v2/utils"
	"golang.org/x/crypto/sha3"
)

func findHeraModDown(numRound int, paramIndex int, radix int, fullCoeffs bool) {
	var err error

	var kgen ckks_fv.KeyGenerator
	var fvEncoder ckks_fv.MFVEncoder
	var sk *ckks_fv.SecretKey
	var pk *ckks_fv.PublicKey
	var fvEncryptor ckks_fv.MFVEncryptor
	var fvDecryptor ckks_fv.MFVDecryptor
	var fvEvaluator ckks_fv.MFVEvaluator
	var fvNoiseEstimator ckks_fv.MFVNoiseEstimator
	var hera ckks_fv.MFVHera

	var nonces [][]byte
	var key []uint64
	var stCt []*ckks_fv.Ciphertext
	var keystream [][]uint64

	var heraModDown []int
	var stcModDown []int

	// RtF parameters
	// Four sets of parameters (index 0 to 3) ensuring 128 bit of security
	// are available in github.com/smilecjf/lattigo/v2/ckks_fv/rtf_params
	// LogSlots is hardcoded in the parameters, but can be changed from 4 to 15.
	// When changing logSlots make sure that the number of levels allocated to CtS is
	// smaller or equal to logSlots.

	hbtpParams := ckks_fv.RtFParams[paramIndex]
	params, err := hbtpParams.Params()
	if err != nil {
		panic(err)
	}

	// fullCoeffs denotes whether full coefficients are used for data encoding
	if fullCoeffs {
		params.SetLogFVSlots(params.LogN())
	} else {
		params.SetLogFVSlots(params.LogSlots())
	}

	// Scheme context and keys
	kgen = ckks_fv.NewKeyGenerator(params)

	sk, pk = kgen.GenKeyPairSparse(hbtpParams.H)

	fvEncoder = ckks_fv.NewMFVEncoder(params)

	fvEncryptor = ckks_fv.NewMFVEncryptorFromPk(params, pk)
	fvDecryptor = ckks_fv.NewMFVDecryptor(params, sk)
	fvNoiseEstimator = ckks_fv.NewMFVNoiseEstimator(params, sk)

	pDcds := fvEncoder.GenSlotToCoeffMatFV(radix)
	rotations := kgen.GenRotationIndexesForSlotsToCoeffsMat(pDcds)
	rotkeys := kgen.GenRotationKeysForRotations(rotations, true, sk)
	rlk := kgen.GenRelinearizationKey(sk)

	fvEvaluator = ckks_fv.NewMFVEvaluator(params, ckks_fv.EvaluationKey{Rlk: rlk, Rtks: rotkeys}, pDcds)

	// Generating data set
	key = make([]uint64, 16)
	for i := 0; i < 16; i++ {
		key[i] = uint64(i + 1) // Use (1, ..., 16) for testing
	}

	nonces = make([][]byte, params.FVSlots())
	for i := 0; i < params.FVSlots(); i++ {
		nonces[i] = make([]byte, 64)
		rand.Read(nonces[i])
	}

	keystream = make([][]uint64, params.FVSlots())
	for i := 0; i < params.FVSlots(); i++ {
		keystream[i] = plainHera(numRound, nonces[i], key, params.PlainModulus())
	}

	// Find proper nbInitModDown value for fvHera
	fmt.Println("=========== Start to find nbInitModDown ===========")
	hera = ckks_fv.NewMFVHera(numRound, params, fvEncoder, fvEncryptor, fvEvaluator, 0)
	heKey := hera.EncKey(key)
	stCt = hera.CryptNoModSwitch(nonces, heKey)

	invBudgets := make([]int, 16)
	minInvBudget := int((^uint(0)) >> 1) // MaxInt
	for i := 0; i < 16; i++ {
		ksSlot := fvEvaluator.SlotsToCoeffsNoModSwitch(stCt[i])

		invBudgets[i] = fvNoiseEstimator.InvariantNoiseBudget(ksSlot)
		if invBudgets[i] < minInvBudget {
			minInvBudget = invBudgets[i]
		}
		fvEvaluator.ModSwitchMany(ksSlot, ksSlot, ksSlot.Level())

		ksCt := fvDecryptor.DecryptNew(ksSlot)
		ksCoef := ckks_fv.NewPlaintextRingT(params)
		fvEncoder.DecodeRingT(ksCt, ksCoef)

		for j := 0; j < params.FVSlots(); j++ {
			br_j := utils.BitReverse64(uint64(j), uint64(params.LogN()))

			if ksCoef.Element.Value()[0].Coeffs[0][br_j] != keystream[j][i] {
				fmt.Printf("[-] Validity failed")
				os.Exit(0)
			}
		}
	}
	fmt.Printf("Budget info : min %d in %v\n", minInvBudget, invBudgets)

	qi := params.Qi()
	qiCount := params.QiCount()
	logQi := make([]int, qiCount)
	for i := 0; i < qiCount; i++ {
		logQi[i] = int(math.Round(math.Log2(float64(qi[i]))))
	}

	nbInitModDown := 0
	cutBits := logQi[qiCount-1]
	for cutBits+40 < minInvBudget { // if minInvBudget is too close to cutBits, decryption can be failed
		nbInitModDown++
		cutBits += logQi[qiCount-nbInitModDown-1]
	}
	fmt.Printf("Preferred nbInitModDown = %d\n\n", nbInitModDown)

	fmt.Println("=========== Start to find HeraModDown & StcModDown ===========")
	hera = ckks_fv.NewMFVHera(numRound, params, fvEncoder, fvEncryptor, fvEvaluator, nbInitModDown)
	heKey = hera.EncKey(key)
	stCt, heraModDown = hera.CryptAutoModSwitch(nonces, heKey, fvNoiseEstimator)
	_, stcModDown = fvEvaluator.SlotsToCoeffsAutoModSwitch(stCt[0], fvNoiseEstimator)
	for i := 0; i < 16; i++ {
		ksSlot := fvEvaluator.SlotsToCoeffs(stCt[i], stcModDown)
		if ksSlot.Level() > 0 {
			fvEvaluator.ModSwitchMany(ksSlot, ksSlot, ksSlot.Level())
		}

		ksCt := fvDecryptor.DecryptNew(ksSlot)
		ksCoef := ckks_fv.NewPlaintextRingT(params)
		fvEncoder.DecodeRingT(ksCt, ksCoef)

		for j := 0; j < params.FVSlots(); j++ {
			br_j := utils.BitReverse64(uint64(j), uint64(params.LogN()))

			if ksCoef.Element.Value()[0].Coeffs[0][br_j] != keystream[j][i] {
				fmt.Printf("[-] Validity failed")
				os.Exit(0)
			}
		}
	}

	fmt.Printf("Hera modDown : %v\n", heraModDown)
	fmt.Printf("SlotsToCoeffs modDown : %v\n", stcModDown)
}

func plainHera(roundNum int, nonce []byte, key []uint64, plainModulus uint64) (state []uint64) {
	nr := roundNum
	xof := sha3.NewShake256()
	xof.Write(nonce)
	state = make([]uint64, 16)

	rks := make([][]uint64, nr+1)

	for r := 0; r <= nr; r++ {
		rks[r] = make([]uint64, 16)
		for st := 0; st < 16; st++ {
			rks[r][st] = ckks_fv.SampleZqx(xof, plainModulus) * key[st] % plainModulus
		}
	}

	for i := 0; i < 16; i++ {
		state[i] = uint64(i + 1)
	}

	// round0
	for st := 0; st < 16; st++ {
		state[st] = (state[st] + rks[0][st]) % plainModulus
	}

	for r := 1; r < roundNum; r++ {
		for col := 0; col < 4; col++ {
			y0 := 2*state[col] + 3*state[col+4] + 1*state[col+8] + 1*state[col+12]
			y1 := 2*state[col+4] + 3*state[col+8] + 1*state[col+12] + 1*state[col]
			y2 := 2*state[col+8] + 3*state[col+12] + 1*state[col] + 1*state[col+4]
			y3 := 2*state[col+12] + 3*state[col] + 1*state[col+4] + 1*state[col+8]

			state[col] = y0 % plainModulus
			state[col+4] = y1 % plainModulus
			state[col+8] = y2 % plainModulus
			state[col+12] = y3 % plainModulus
		}

		for row := 0; row < 4; row++ {
			y0 := 2*state[4*row] + 3*state[4*row+1] + 1*state[4*row+2] + 1*state[4*row+3]
			y1 := 2*state[4*row+1] + 3*state[4*row+2] + 1*state[4*row+3] + 1*state[4*row]
			y2 := 2*state[4*row+2] + 3*state[4*row+3] + 1*state[4*row] + 1*state[4*row+1]
			y3 := 2*state[4*row+3] + 3*state[4*row] + 1*state[4*row+1] + 1*state[4*row+2]

			state[4*row] = y0 % plainModulus
			state[4*row+1] = y1 % plainModulus
			state[4*row+2] = y2 % plainModulus
			state[4*row+3] = y3 % plainModulus
		}

		for st := 0; st < 16; st++ {
			state[st] = (state[st] * state[st] % plainModulus) * state[st] % plainModulus
		}

		for st := 0; st < 16; st++ {
			state[st] = (state[st] + rks[r][st]) % plainModulus
		}
	}
	for col := 0; col < 4; col++ {
		y0 := 2*state[col] + 3*state[col+4] + 1*state[col+8] + 1*state[col+12]
		y1 := 2*state[col+4] + 3*state[col+8] + 1*state[col+12] + 1*state[col]
		y2 := 2*state[col+8] + 3*state[col+12] + 1*state[col] + 1*state[col+4]
		y3 := 2*state[col+12] + 3*state[col] + 1*state[col+4] + 1*state[col+8]

		state[col] = y0 % plainModulus
		state[col+4] = y1 % plainModulus
		state[col+8] = y2 % plainModulus
		state[col+12] = y3 % plainModulus
	}

	for row := 0; row < 4; row++ {
		y0 := 2*state[4*row] + 3*state[4*row+1] + 1*state[4*row+2] + 1*state[4*row+3]
		y1 := 2*state[4*row+1] + 3*state[4*row+2] + 1*state[4*row+3] + 1*state[4*row]
		y2 := 2*state[4*row+2] + 3*state[4*row+3] + 1*state[4*row] + 1*state[4*row+1]
		y3 := 2*state[4*row+3] + 3*state[4*row] + 1*state[4*row+1] + 1*state[4*row+2]

		state[4*row] = y0 % plainModulus
		state[4*row+1] = y1 % plainModulus
		state[4*row+2] = y2 % plainModulus
		state[4*row+3] = y3 % plainModulus
	}

	for st := 0; st < 16; st++ {
		state[st] = (state[st] * state[st] % plainModulus) * state[st] % plainModulus
	}

	for col := 0; col < 4; col++ {
		y0 := 2*state[col] + 3*state[col+4] + 1*state[col+8] + 1*state[col+12]
		y1 := 2*state[col+4] + 3*state[col+8] + 1*state[col+12] + 1*state[col]
		y2 := 2*state[col+8] + 3*state[col+12] + 1*state[col] + 1*state[col+4]
		y3 := 2*state[col+12] + 3*state[col] + 1*state[col+4] + 1*state[col+8]

		state[col] = y0 % plainModulus
		state[col+4] = y1 % plainModulus
		state[col+8] = y2 % plainModulus
		state[col+12] = y3 % plainModulus
	}

	for row := 0; row < 4; row++ {
		y0 := 2*state[4*row] + 3*state[4*row+1] + 1*state[4*row+2] + 1*state[4*row+3]
		y1 := 2*state[4*row+1] + 3*state[4*row+2] + 1*state[4*row+3] + 1*state[4*row]
		y2 := 2*state[4*row+2] + 3*state[4*row+3] + 1*state[4*row] + 1*state[4*row+1]
		y3 := 2*state[4*row+3] + 3*state[4*row] + 1*state[4*row+1] + 1*state[4*row+2]

		state[4*row] = y0 % plainModulus
		state[4*row+1] = y1 % plainModulus
		state[4*row+2] = y2 % plainModulus
		state[4*row+3] = y3 % plainModulus
	}

	for st := 0; st < 16; st++ {
		state[st] = (state[st] + rks[roundNum][st]) % plainModulus
	}
	return
}

func plainRubato(blocksize int, numRound int, nonce []byte, counter []byte, key []uint64, plainModulus uint64) (state []uint64) {
	xof := sha3.NewShake256()
	xof.Write(nonce)
	xof.Write(counter)
	state = make([]uint64, blocksize)

	rks := make([][]uint64, numRound+1)

	for r := 0; r <= numRound; r++ {
		rks[r] = make([]uint64, blocksize)
		for i := 0; i < blocksize; i++ {
			rks[r][i] = ckks_fv.SampleZqx(xof, plainModulus) * key[i] % plainModulus
			// rks[r][i] = uint64(i+1) * key[i] % t
		}
	}

	for i := 0; i < blocksize; i++ {
		state[i] = uint64(i + 1)
	}

	// Initial AddRoundKey
	for i := 0; i < blocksize; i++ {
		state[i] = (state[i] + rks[0][i]) % plainModulus
	}

	// Round Functions
	for r := 1; r < numRound; r++ {
		rubatoLinearLayer(state, plainModulus)
		rubatoFeistel(state, plainModulus)
		for i := 0; i < blocksize; i++ {
			state[i] = (state[i] + rks[r][i]) % plainModulus
		}
	}

	// Finalization
	rubatoLinearLayer(state, plainModulus)
	rubatoFeistel(state, plainModulus)
	rubatoLinearLayer(state, plainModulus)
	for i := 0; i < blocksize; i++ {
		state[i] = (state[i] + rks[numRound][i]) % plainModulus
	}
	state = state[0 : blocksize-4]

	return
}

func rubatoLinearLayer(state []uint64, plainModulus uint64) {
	blocksize := len(state)
	buf := make([]uint64, blocksize)

	if blocksize == 16 {
		// MixColumns
		for row := 0; row < 4; row++ {
			for col := 0; col < 4; col++ {
				buf[row*4+col] = 2 * state[row*4+col]
				buf[row*4+col] += 3 * state[((row+1)%4)*4+col]
				buf[row*4+col] += state[((row+2)%4)*4+col]
				buf[row*4+col] += state[((row+3)%4)*4+col]
				buf[row*4+col] %= plainModulus
			}
		}
		// MixRows
		for row := 0; row < 4; row++ {
			for col := 0; col < 4; col++ {
				state[row*4+col] = 2 * buf[row*4+col]
				state[row*4+col] += 3 * buf[row*4+(col+1)%4]
				state[row*4+col] += buf[row*4+(col+2)%4]
				state[row*4+col] += buf[row*4+(col+3)%4]
				state[row*4+col] %= plainModulus
			}
		}
	} else if blocksize == 36 {
		// MixColumns
		for row := 0; row < 6; row++ {
			for col := 0; col < 6; col++ {
				buf[row*6+col] = 4 * state[row*6+col]
				buf[row*6+col] += 2 * state[((row+1)%6)*6+col]
				buf[row*6+col] += 4 * state[((row+2)%6)*6+col]
				buf[row*6+col] += 3 * state[((row+3)%6)*6+col]
				buf[row*6+col] += state[((row+4)%6)*6+col]
				buf[row*6+col] += state[((row+5)%6)*6+col]
				buf[row*6+col] %= plainModulus
			}
		}
		// MixRows
		for row := 0; row < 6; row++ {
			for col := 0; col < 6; col++ {
				state[row*6+col] = 4 * buf[row*6+col]
				state[row*6+col] += 2 * buf[row*6+(col+1)%6]
				state[row*6+col] += 4 * buf[row*6+(col+2)%6]
				state[row*6+col] += 3 * buf[row*6+(col+3)%6]
				state[row*6+col] += buf[row*6+(col+4)%6]
				state[row*6+col] += buf[row*6+(col+5)%6]
				state[row*6+col] %= plainModulus
			}
		}
	} else if blocksize == 64 {
		// MixColumns
		for row := 0; row < 8; row++ {
			for col := 0; col < 8; col++ {
				buf[row*8+col] = 5 * state[row*8+col]
				buf[row*8+col] += 3 * state[((row+1)%8)*8+col]
				buf[row*8+col] += 4 * state[((row+2)%8)*8+col]
				buf[row*8+col] += 3 * state[((row+3)%8)*8+col]
				buf[row*8+col] += 6 * state[((row+4)%8)*8+col]
				buf[row*8+col] += 2 * state[((row+5)%8)*8+col]
				buf[row*8+col] += state[((row+6)%8)*8+col]
				buf[row*8+col] += state[((row+7)%8)*8+col]
				buf[row*8+col] %= plainModulus
			}
		}
		// MixRows
		for row := 0; row < 8; row++ {
			for col := 0; col < 8; col++ {
				state[row*8+col] = 5 * buf[row*8+col]
				state[row*8+col] += 3 * buf[row*8+(col+1)%8]
				state[row*8+col] += 4 * buf[row*8+(col+2)%8]
				state[row*8+col] += 3 * buf[row*8+(col+3)%8]
				state[row*8+col] += 6 * buf[row*8+(col+4)%8]
				state[row*8+col] += 2 * buf[row*8+(col+5)%8]
				state[row*8+col] += buf[row*8+(col+6)%8]
				state[row*8+col] += buf[row*8+(col+7)%8]
				state[row*8+col] %= plainModulus
			}
		}
	} else {
		panic("Invalid blocksize")
	}
}

func rubatoFeistel(state []uint64, plainModulus uint64) {
	blocksize := len(state)
	buf := make([]uint64, blocksize)

	for i := 0; i < blocksize; i++ {
		buf[i] = state[i]
	}

	for i := 1; i < blocksize; i++ {
		state[i] = (buf[i] + buf[i-1]*buf[i-1]) % plainModulus
	}
}

func testPlainRubato() {
	numRound := 5
	blocksize := 16 // Should be 16, 36 or 64
	nonce := make([]byte, 8)
	counter := make([]byte, 8)
	key := make([]uint64, blocksize)
	t := uint64(0x3ffc0001)

	// Generate secret key
	for i := 0; i < blocksize; i++ {
		key[i] = uint64(i+1) % t
	}

	// Generate nonce
	rand.Read(nonce)

	state := plainRubato(blocksize, numRound, nonce, counter, key, t)
	fmt.Println(state)
}

func testFVRubato(blocksize int, numRound int) {
	var kgen ckks_fv.KeyGenerator
	var fvEncoder ckks_fv.MFVEncoder
	var sk *ckks_fv.SecretKey
	var pk *ckks_fv.PublicKey
	var fvEncryptor ckks_fv.MFVEncryptor
	var fvDecryptor ckks_fv.MFVDecryptor
	var fvEvaluator ckks_fv.MFVEvaluator
	// var fvNoiseEstimator ckks_fv.MFVNoiseEstimator
	var rubato ckks_fv.MFVRubato

	var nonces [][]byte
	var key []uint64
	// var stCt []*ckks_fv.Ciphertext
	var keystream [][]uint64
	var keystreamCt []*ckks_fv.Ciphertext

	params := ckks_fv.DefaultFVParams[3].WithPlainModulus(0x1ffc0001)

	// Scheme context and keys
	fmt.Println("Key generation...")
	kgen = ckks_fv.NewKeyGenerator(params)

	sk, pk = kgen.GenKeyPairSparse(192)

	fvEncoder = ckks_fv.NewMFVEncoder(params)
	fvEncryptor = ckks_fv.NewMFVEncryptorFromPk(params, pk)
	fvDecryptor = ckks_fv.NewMFVDecryptor(params, sk)
	// fvNoiseEstimator = ckks_fv.NewMFVNoiseEstimator(params, sk)

	rlk := kgen.GenRelinearizationKey(sk)
	fvEvaluator = ckks_fv.NewMFVEvaluator(params, ckks_fv.EvaluationKey{Rlk: rlk}, nil)

	// Generating data set
	key = make([]uint64, blocksize)
	for i := 0; i < blocksize; i++ {
		key[i] = uint64(i + 1)
	}

	nonces = make([][]byte, params.FVSlots())
	for i := 0; i < params.FVSlots(); i++ {
		nonces[i] = make([]byte, 64)
		rand.Read(nonces[i])
	}
	counter := make([]byte, 64)

	// Compute plain Rubato keystream
	fmt.Println("Computing plain keystream...")
	keystream = make([][]uint64, params.FVSlots())
	for i := 0; i < params.FVSlots(); i++ {
		keystream[i] = plainRubato(blocksize, numRound, nonces[i], counter, key, params.PlainModulus())
	}

	// Evaluate the Rubato keystream
	fmt.Println("Evaluating HE keystream...")
	rubato = ckks_fv.NewMFVRubato(blocksize, numRound, params, fvEncoder, fvEncryptor, fvEvaluator, 0)
	hekey := rubato.EncKey(key)
	keystreamCt = rubato.CryptNoModSwitch(nonces, counter, hekey)

	// Decrypt and decode the Rubato keystream
	for i := 0; i < blocksize-4; i++ {
		val := fvEncoder.DecodeUintSmallNew(fvDecryptor.DecryptNew(keystreamCt[i]))
		resString := fmt.Sprintf("keystream[%d]: he(%d), plain(%d)", i, val[0], keystream[0][i])
		fmt.Println(resString)
	}
}

func main() {
	findHeraModDown(4, 0, 2, false)
	// testPlainRubato()
	// testFVRubato(64, 10)
}
