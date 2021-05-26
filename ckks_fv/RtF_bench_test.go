package ckks_fv

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/ldsec/lattigo/v2/utils"
	"golang.org/x/crypto/sha3"
)

func BenchmarkRtF(b *testing.B) {
	var err error

	var hbtp *HalfBootstrapper
	var kgen KeyGenerator
	var fvEncoder MFVEncoder
	var ckksEncoder CKKSEncoder
	var sk *SecretKey
	var pk *PublicKey
	var fvEncryptor MFVEncryptor
	var fvEvaluator MFVEvaluator
	var ckksEvaluator CKKSEvaluator
	// var fvNoiseEstimator MFVNoiseEstimator
	var plainCKKSRingTs []*PlaintextRingT
	var plaintexts []*Plaintext
	var hera MFVHera

	var data [][]float64
	var nonces [][]byte
	var key []uint64
	var keystream [][]uint64
	var fvKeystreams []*Ciphertext

	// Half-Bootstrapping parameters
	// Four sets of parameters (index 0 to 3) ensuring 128 bit of security
	// are available in github.com/ldsec/lattigo/v2/ckks/halfboot_params
	// LogSlots is hardcoded to 15 in the parameters, but can be changed from 1 to 15.
	// When changing logSlots make sure that the number of levels allocated to CtS is
	// smaller or equal to logSlots.

	numRound := 5
	hbtpParams := RtFParams[2]
	heraModDown := HeraModDownParams80[2]
	stcModDown := StcModDownParams80[2]
	heraModDown = []int{4, 2, 2, 2, 2, 2}
	stcModDown = []int{0, 1, 1, 1, 1, 1, 0, 1}
	params, err := hbtpParams.Params()
	if err != nil {
		panic(err)
	}
	messageScaling := float64(params.T()) / (2 * hbtpParams.MessageRatio)

	fullCoeffs := true
	fullCoeffs = fullCoeffs && (params.LogN() == params.LogSlots()+1)
	if fullCoeffs {
		params.SetLogFVSlots(params.LogN())
	} else {
		params.SetLogFVSlots(params.LogSlots())
	}

	// Scheme context and keys
	kgen = NewKeyGenerator(params)

	sk, pk = kgen.GenKeyPairSparse(hbtpParams.H)

	fvEncoder = NewMFVEncoder(params)
	ckksEncoder = NewCKKSEncoder(params)
	fvEncryptor = NewMFVEncryptorFromPk(params, pk)

	// Generating half-bootstrapping keys
	rotationsHalfBoot := kgen.GenRotationIndexesForHalfBoot(params.LogSlots(), hbtpParams)
	pDcds := fvEncoder.GenSlotToCoeffMatFV()
	rotationsStC := kgen.GenRotationIndexesForSlotsToCoeffsMat(pDcds)
	rotations := append(rotationsHalfBoot, rotationsStC...)
	rotkeys := kgen.GenRotationKeysForRotations(rotations, true, sk)
	rlk := kgen.GenRelinearizationKey(sk)
	hbtpKey := BootstrappingKey{Rlk: rlk, Rtks: rotkeys}

	if hbtp, err = NewHalfBootstrapper(params, hbtpParams, hbtpKey); err != nil {
		panic(err)
	}

	fvEvaluator = NewMFVEvaluator(params, EvaluationKey{Rlk: rlk, Rtks: rotkeys}, pDcds)
	// fvNoiseEstimator = NewMFVNoiseEstimator(params, sk)
	ckksEvaluator = NewCKKSEvaluator(params, EvaluationKey{Rlk: rlk, Rtks: rotkeys})

	// Encode float data added by keystream to plaintext coefficients
	coeffs := make([][]float64, 16)
	for s := 0; s < 16; s++ {
		coeffs[s] = make([]float64, params.N())
	}

	key = make([]uint64, 16)
	for i := 0; i < 16; i++ {
		key[i] = uint64(i + 1) // Use (1, ..., 16) for testing
	}

	if fullCoeffs {
		data = make([][]float64, 16)
		for s := 0; s < 16; s++ {
			data[s] = make([]float64, params.N())
			for i := 0; i < params.N(); i++ {
				data[s][i] = utils.RandFloat64(-1, 1)
			}
		}

		nonces = make([][]byte, params.N())
		for i := 0; i < params.N(); i++ {
			nonces[i] = make([]byte, 64)
			rand.Read(nonces[i])
		}

		keystream = make([][]uint64, params.N())
		for i := 0; i < params.N(); i++ {
			keystream[i] = plainHera(numRound, nonces[i], key, params.T())
		}

		for s := 0; s < 16; s++ {
			for i := 0; i < params.N()/2; i++ {
				j := utils.BitReverse64(uint64(i), uint64(params.LogN()-1))
				coeffs[s][j] = data[s][i]
				coeffs[s][j+uint64(params.N()/2)] = data[s][i+params.N()/2]
			}
		}

		plainCKKSRingTs = make([]*PlaintextRingT, 16)
		for s := 0; s < 16; s++ {
			plainCKKSRingTs[s] = ckksEncoder.EncodeCoeffsRingTNew(coeffs[s], messageScaling)
			poly := plainCKKSRingTs[s].Value()[0]
			for i := 0; i < params.N(); i++ {
				j := utils.BitReverse64(uint64(i), uint64(params.LogN()))
				poly.Coeffs[0][j] = (poly.Coeffs[0][j] + keystream[i][s]) % params.T()
			}
		}
	} else {
		data = make([][]float64, 16)
		for s := 0; s < 16; s++ {
			data[s] = make([]float64, params.Slots())
			for i := 0; i < params.Slots(); i++ {
				data[s][i] = utils.RandFloat64(-1, 1)
			}
		}

		nonces = make([][]byte, params.Slots())
		for i := 0; i < params.Slots(); i++ {
			nonces[i] = make([]byte, 64)
			rand.Read(nonces[i])
		}

		keystream = make([][]uint64, params.Slots())
		for i := 0; i < params.Slots(); i++ {
			keystream[i] = plainHera(numRound, nonces[i], key, params.T())
		}

		for s := 0; s < 16; s++ {
			for i := 0; i < params.Slots()/2; i++ {
				j := utils.BitReverse64(uint64(i), uint64(params.LogN()-1))
				coeffs[s][j] = data[s][i]
				coeffs[s][j+uint64(params.N()/2)] = data[s][i+params.Slots()/2]
			}
		}

		plainCKKSRingTs = make([]*PlaintextRingT, 16)
		for s := 0; s < 16; s++ {
			plainCKKSRingTs[s] = ckksEncoder.EncodeCoeffsRingTNew(coeffs[s], messageScaling)
			poly := plainCKKSRingTs[s].Value()[0]
			for i := 0; i < params.Slots(); i++ {
				j := utils.BitReverse64(uint64(i), uint64(params.LogN()))
				poly.Coeffs[0][j] = (poly.Coeffs[0][j] + keystream[i][s]) % params.T()
			}
		}

	}

	plaintexts = make([]*Plaintext, 16)

	for s := 0; s < 16; s++ {
		plaintexts[s] = NewPlaintextFVLvl(params, 0)
		fvEncoder.FVScaleUp(plainCKKSRingTs[s], plaintexts[s])
	}

	hera = NewMFVHera(numRound, params, fvEncoder, fvEncryptor, fvEvaluator, heraModDown[0])
	kCt := hera.EncKey(key)

	// FV Keystream
	benchOffLat := fmt.Sprintf("RtF Offline Latency With RtFParam[%d]", 1)
	b.Run(benchOffLat, func(b *testing.B) {
		fvKeystreams = hera.Crypt(nonces, kCt, heraModDown)
		for i := 0; i < 1; i++ {
			fvKeystreams[i] = fvEvaluator.SlotsToCoeffs(fvKeystreams[i], stcModDown)
			fvEvaluator.ModSwitchMany(fvKeystreams[i], fvKeystreams[i], fvKeystreams[i].Level())
		}
	})
	/* We assume that b.N == 1 */
	benchOffThrput := fmt.Sprintf("RtF Offline Throughput With RtFParam[%d]", 1)
	b.Run(benchOffThrput, func(b *testing.B) {
		for i := 1; i < 16; i++ {
			fvKeystreams[i] = fvEvaluator.SlotsToCoeffs(fvKeystreams[i], stcModDown)
			fvEvaluator.ModSwitchMany(fvKeystreams[i], fvKeystreams[i], fvKeystreams[i].Level())
		}
	})

	benchOnline := fmt.Sprintf("RtF Online Lat with RtFParam[%d] x1", 1)
	b.Run(benchOnline, func(b *testing.B) {
		// Encrypt and mod switch to the lowest level

		ciphertext := NewCiphertextFVLvl(params, 1, 0)
		ciphertext.Value()[0] = plaintexts[0].Value()[0].CopyNew()
		fvEvaluator.Sub(ciphertext, fvKeystreams[0], ciphertext)
		fvEvaluator.TransformToNTT(ciphertext, ciphertext)
		ciphertext.SetScale(float64(params.Qi()[0]) / float64(params.T()) * messageScaling)

		// Half-Bootstrap the ciphertext (homomorphic evaluation of ModRaise -> SubSum -> CtS -> EvalMod)
		// It takes a ciphertext at level 0 (if not at level 0, then it will reduce it to level 0)
		// and returns a ciphertext at level MaxLevel - k, where k is the depth of the bootstrapping circuit.
		// Difference from the bootstrapping is that the last StC is missing.
		// CAUTION: the scale of the ciphertext MUST be equal (or very close) to params.Scale
		// To equalize the scale, the function evaluator.SetScale(ciphertext, parameters.Scale) can be used at the expense of one level.
		if fullCoeffs {
			hbtp.HalfBoot(ciphertext, false)
		} else {
			ctBoot0, ctBoot1 := hbtp.HalfBoot(ciphertext, true)
			ctBoot := ckksEvaluator.RotateNew(ctBoot1, params.Slots()/2)
			ckksEvaluator.Add(ctBoot, ctBoot0, ctBoot)
		}
	})
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
			rks[r][st] = SampleZtx(xof, t) * key[st] % t
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
