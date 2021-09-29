package ckks_fv

import (
	"crypto/rand"
	"fmt"
	"math"
	"testing"

	"github.com/ldsec/lattigo/v2/utils"
	"golang.org/x/crypto/sha3"
)

// Benchmark RtF framework for 80-bit security full-slots parameter
func BenchmarkRtF80f(b *testing.B) {
	benchmarkRtF(b, "80f", 4, 0, 2, true)
}

// Benchmark RtF framework for 80-bit security 4-slots parameter
func BenchmarkRtF80s(b *testing.B) {
	benchmarkRtF(b, "80s", 4, 1, 0, false)
}

// Benchmark RtF framework for 80-bit security full-slots parameter with arcsine evaluation
func BenchmarkRtF80af(b *testing.B) {
	benchmarkRtF(b, "80af", 4, 2, 2, true)
}

// Benchmark RtF framework for 80-bit security 4-slots parameter with arcsine evaluation
func BenchmarkRtF80as(b *testing.B) {
	benchmarkRtF(b, "80as", 4, 3, 0, false)
}

// Benchmark RtF framework for 128-bit security full-slots parameter
func BenchmarkRtF128f(b *testing.B) {
	benchmarkRtF(b, "128f", 5, 0, 2, true)
}

// Benchmark RtF framework for 128-bit security 4-slots parameter
func BenchmarkRtF128s(b *testing.B) {
	benchmarkRtF(b, "128s", 5, 1, 0, false)
}

// Benchmark RtF framework for 128-bit security full-slots parameter with arcsine evaluation
func BenchmarkRtF128af(b *testing.B) {
	benchmarkRtF(b, "128af", 5, 2, 2, true)
}

// Benchmark RtF framework for 128-bit security 4-slots parameter with arcsine evaluation
func BenchmarkRtF128as(b *testing.B) {
	benchmarkRtF(b, "128as", 5, 3, 2, false)
}

func benchmarkRtF(b *testing.B, name string, numRound int, paramIndex int, radix int, fullCoeffs bool) {
	var err error

	var hbtp *HalfBootstrapper
	var kgen KeyGenerator
	var fvEncoder MFVEncoder
	var ckksEncoder CKKSEncoder
	var ckksDecryptor CKKSDecryptor
	var sk *SecretKey
	var pk *PublicKey
	var fvEncryptor MFVEncryptor
	var fvEvaluator MFVEvaluator
	var plainCKKSRingTs []*PlaintextRingT
	var plaintexts []*Plaintext
	var hera MFVHera

	var data [][]float64
	var nonces [][]byte
	var key []uint64
	var keystream [][]uint64
	var fvKeystreams []*Ciphertext

	// RtF parameters
	// Four sets of parameters (index 0 to 3) ensuring 128 bit of security
	// are available in github.com/smilecjf/lattigo/v2/ckks_fv/rtf_params
	// LogSlots is hardcoded in the parameters, but can be changed from 4 to 15.
	// When changing logSlots make sure that the number of levels allocated to CtS is
	// smaller or equal to logSlots.

	hbtpParams := RtFParams[paramIndex]
	params, err := hbtpParams.Params()
	if err != nil {
		panic(err)
	}
	messageScaling := float64(params.T()) / hbtpParams.MessageRatio

	// HERA parameters in RtF
	var heraModDown, stcModDown []int
	if numRound == 4 {
		heraModDown = HeraModDownParams80[paramIndex]
		stcModDown = StcModDownParams80[paramIndex]
	} else {
		heraModDown = HeraModDownParams128[paramIndex]
		stcModDown = StcModDownParams128[paramIndex]
	}

	// fullCoeffs denotes whether full coefficients are used for data encoding
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
	ckksDecryptor = NewCKKSDecryptor(params, sk)

	// Generating half-bootstrapping keys
	rotationsHalfBoot := kgen.GenRotationIndexesForHalfBoot(params.LogSlots(), hbtpParams)
	pDcds := fvEncoder.GenSlotToCoeffMatFV(radix)
	rotationsStC := kgen.GenRotationIndexesForSlotsToCoeffsMat(pDcds)
	rotations := append(rotationsHalfBoot, rotationsStC...)
	if !fullCoeffs {
		rotations = append(rotations, params.Slots()/2)
	}
	rotkeys := kgen.GenRotationKeysForRotations(rotations, true, sk)
	rlk := kgen.GenRelinearizationKey(sk)
	hbtpKey := BootstrappingKey{Rlk: rlk, Rtks: rotkeys}

	if hbtp, err = NewHalfBootstrapper(params, hbtpParams, hbtpKey); err != nil {
		panic(err)
	}

	// Encode float data added by keystream to plaintext coefficients
	fvEvaluator = NewMFVEvaluator(params, EvaluationKey{Rlk: rlk, Rtks: rotkeys}, pDcds)
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
	benchOffLat := fmt.Sprintf("RtF Offline Latency")
	b.Run(benchOffLat, func(b *testing.B) {
		fvKeystreams = hera.Crypt(nonces, kCt, heraModDown)
		for i := 0; i < 1; i++ {
			fvKeystreams[i] = fvEvaluator.SlotsToCoeffs(fvKeystreams[i], stcModDown)
			fvEvaluator.ModSwitchMany(fvKeystreams[i], fvKeystreams[i], fvKeystreams[i].Level())
		}
	})
	/* We assume that b.N == 1 */
	benchOffThrput := fmt.Sprintf("RtF Offline Throughput")
	b.Run(benchOffThrput, func(b *testing.B) {
		for i := 1; i < 16; i++ {
			fvKeystreams[i] = fvEvaluator.SlotsToCoeffs(fvKeystreams[i], stcModDown)
			fvEvaluator.ModSwitchMany(fvKeystreams[i], fvKeystreams[i], fvKeystreams[i].Level())
		}
	})

	var ctBoot *Ciphertext
	benchOnline := fmt.Sprintf("RtF Online Lat x1")
	b.Run(benchOnline, func(b *testing.B) {
		// Encrypt and mod switch to the lowest level
		ciphertext := NewCiphertextFVLvl(params, 1, 0)
		ciphertext.Value()[0] = plaintexts[0].Value()[0].CopyNew()
		fvEvaluator.Sub(ciphertext, fvKeystreams[0], ciphertext)
		fvEvaluator.TransformToNTT(ciphertext, ciphertext)
		ciphertext.SetScale(math.Exp2(math.Round(math.Log2(float64(params.Qi()[0]) / float64(params.T()) * messageScaling))))

		// Half-Bootstrap the ciphertext (homomorphic evaluation of ModRaise -> SubSum -> CtS -> EvalMod)
		// It takes a ciphertext at level 0 (if not at level 0, then it will reduce it to level 0)
		// and returns a ciphertext at level MaxLevel - k, where k is the depth of the bootstrapping circuit.
		// Difference from the bootstrapping is that the last StC is missing.
		// CAUTION: the scale of the ciphertext MUST be equal (or very close) to params.Scale
		// To equalize the scale, the function evaluator.SetScale(ciphertext, parameters.Scale) can be used at the expense of one level.
		if fullCoeffs {
			ctBoot, _ = hbtp.HalfBoot(ciphertext, false)
		} else {
			ctBoot, _ = hbtp.HalfBoot(ciphertext, true)
		}
	})
	valuesWant := make([]complex128, params.Slots())
	for i := 0; i < params.Slots(); i++ {
		valuesWant[i] = complex(data[0][i], 0)
	}

	fmt.Println("Precision of HalfBoot(ciphertext)")
	printDebug(params, ctBoot, valuesWant, ckksDecryptor, ckksEncoder)
}

func printDebug(params *Parameters, ciphertext *Ciphertext, valuesWant []complex128, decryptor CKKSDecryptor, encoder CKKSEncoder) {

	valuesTest := encoder.DecodeComplex(decryptor.DecryptNew(ciphertext), params.LogSlots())
	logSlots := params.LogSlots()
	sigma := params.Sigma()

	fmt.Printf("Level: %d (logQ = %d)\n", ciphertext.Level(), params.LogQLvl(ciphertext.Level()))
	fmt.Printf("Scale: 2^%f\n", math.Log2(ciphertext.Scale()))
	fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	fmt.Printf("ValuesWant: %6.10f %6.10f %6.10f %6.10f...\n", valuesWant[0], valuesWant[1], valuesWant[2], valuesWant[3])

	precStats := GetPrecisionStats(params, encoder, nil, valuesWant, valuesTest, logSlots, sigma)

	fmt.Println(precStats.String())
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
