package main

import (
	"fmt"
	"math"
	"strconv"

	"github.com/ldsec/lattigo/v2/ckks_fv"
	"github.com/ldsec/lattigo/v2/utils"
)

func printDebug(params *ckks_fv.Parameters, ciphertext *ckks_fv.Ciphertext, valuesWant []complex128, decryptor ckks_fv.CKKSDecryptor, encoder ckks_fv.CKKSEncoder) (valuesTest []complex128) {

	valuesTest = encoder.DecodeComplex(decryptor.DecryptNew(ciphertext), params.LogSlots())
	logSlots := params.LogSlots()
	sigma := params.Sigma()

	fmt.Println()
	fmt.Printf("Level: %d (logQ = %d)\n", ciphertext.Level(), params.LogQLvl(ciphertext.Level()))
	fmt.Printf("Scale: 2^%f\n", math.Log2(ciphertext.Scale()))
	fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	fmt.Printf("ValuesWant: %6.10f %6.10f %6.10f %6.10f...\n", valuesWant[0], valuesWant[1], valuesWant[2], valuesWant[3])

	precStats := ckks_fv.GetPrecisionStats(params, encoder, nil, valuesWant, valuesTest, logSlots, sigma)

	fmt.Println(precStats.String())
	fmt.Println()

	return
}

func printDec(ct0 *ckks_fv.Ciphertext, numPrint int, decryptor ckks_fv.MFVDecryptor, encoder ckks_fv.MFVEncoder) {
	decrypted := decryptor.DecryptNew(ct0)
	decoded := encoder.DecodeUintNew(decrypted)
	fmt.Println("  Result:")
	for i := 0; i < numPrint; i++ {
		fmt.Printf("    res[%d]: %d\n", i, decoded[i])
	}
}

func RtF() {
	fmt.Println("==== RtF Framework ====")
	var err error

	var hbtp *ckks_fv.HalfBootstrapper
	var kgen ckks_fv.KeyGenerator
	var fvEncoder ckks_fv.MFVEncoder
	var ckksEncoder ckks_fv.CKKSEncoder
	var sk *ckks_fv.SecretKey
	var pk *ckks_fv.PublicKey
	var fvEncryptor ckks_fv.MFVEncryptor
	var ckksDecryptor ckks_fv.CKKSDecryptor
	var fvEvaluator ckks_fv.MFVEvaluator
	var ckksEvaluator ckks_fv.CKKSEvaluator
	var plainCKKSRingTs []*ckks_fv.PlaintextRingT
	var plaintexts []*ckks_fv.Plaintext
	var hera ckks_fv.MFVHera

	// Half-Bootstrapping parameters
	// Four sets of parameters (index 0 to 3) ensuring 128 bit of security
	// are available in github.com/ldsec/lattigo/v2/ckks/halfboot_params
	// LogSlots is hardcoded to 15 in the parameters, but can be changed from 1 to 15.
	// When changing logSlots make sure that the number of levels allocated to CtS is
	// smaller or equal to logSlots.

	hbtpParams := ckks_fv.DefaultHalfBootParams[0]
	params, err := hbtpParams.Params()
	if err != nil {
		panic(err)
	}
	messageScaling := float64(params.T()) / (2 * hbtpParams.MessageRatio)

	fullCoeffs := false
	fullCoeffs = fullCoeffs && (params.LogN() == params.LogSlots()+1)
	if fullCoeffs {
		params.SetLogFVSlots(params.LogN())
	} else {
		params.SetLogFVSlots(params.LogSlots())
	}

	fmt.Println()
	fmt.Printf("CKKS parameters: logN = %d, logSlots = %d, h = %d, logQP = %d, levels = %d, scale= 2^%f, sigma = %f \n", params.LogN(), params.LogSlots(), hbtpParams.H, params.LogQP(), params.Levels(), math.Log2(params.Scale()), params.Sigma())

	// Scheme context and keys
	kgen = ckks_fv.NewKeyGenerator(params)

	sk, pk = kgen.GenKeyPairSparse(hbtpParams.H)

	fvEncoder = ckks_fv.NewMFVEncoder(params)
	ckksEncoder = ckks_fv.NewCKKSEncoder(params)
	fvEncryptor = ckks_fv.NewMFVEncryptorFromPk(params, pk)
	ckksDecryptor = ckks_fv.NewCKKSDecryptor(params, sk)

	fmt.Println()
	fmt.Println("Generating half-bootstrapping keys...")
	rotationsHalfBoot := kgen.GenRotationIndexesForHalfBoot(params.LogSlots(), hbtpParams)
	pDcds := fvEncoder.GenSlotToCoeffMatFV()
	rotationsStC := kgen.GenRotationIndexesForSlotsToCoeffsMat(pDcds)
	rotations := append(rotationsHalfBoot, rotationsStC...)
	rotkeys := kgen.GenRotationKeysForRotations(rotations, true, sk)
	rlk := kgen.GenRelinearizationKey(sk)
	hbtpKey := ckks_fv.BootstrappingKey{Rlk: rlk, Rtks: rotkeys}

	if hbtp, err = ckks_fv.NewHalfBootstrapper(params, hbtpParams, hbtpKey); err != nil {
		panic(err)
	}
	fmt.Println("Done")

	fvEvaluator = ckks_fv.NewMFVEvaluator(params, ckks_fv.EvaluationKey{Rlk: rlk, Rtks: rotkeys}, pDcds)
	ckksEvaluator = ckks_fv.NewCKKSEvaluator(params, ckks_fv.EvaluationKey{Rlk: rlk, Rtks: rotkeys})

	// Encode float data added by keystream to plaintext coefficients
	fmt.Println()
	fmt.Println("Encode random numbers on coefficients...")
	var data [][]float64
	var nonces [][]byte
	var key []uint64
	var keystream [][]uint64

	coeffs := make([][]float64, 16)
	for s := 0; s < 16; s++ {
		coeffs[s] = make([]float64, params.N())
	}

	numRound := 4
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
			// rand.Read(nonces[i])
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

		plainCKKSRingTs = make([]*ckks_fv.PlaintextRingT, 16)
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
			// rand.Read(nonces[i])
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

		plainCKKSRingTs = make([]*ckks_fv.PlaintextRingT, 16)
		for s := 0; s < 16; s++ {
			plainCKKSRingTs[s] = ckksEncoder.EncodeCoeffsRingTNew(coeffs[s], messageScaling)
			poly := plainCKKSRingTs[s].Value()[0]
			for i := 0; i < params.Slots(); i++ {
				j := utils.BitReverse64(uint64(i), uint64(params.LogN()))
				poly.Coeffs[0][j] = (poly.Coeffs[0][j] + keystream[i][s]) % params.T()
			}
		}

	}

	plaintexts = make([]*ckks_fv.Plaintext, 16)

	for s := 0; s < 16; s++ {
		plaintexts[s] = ckks_fv.NewPlaintextFVLvl(params, 0)
		fvEncoder.FVScaleUp(plainCKKSRingTs[s], plaintexts[s])
	}

	hera = ckks_fv.NewMFVHera(numRound, params, fvEncoder, fvEncryptor, fvEvaluator, nil)
	hera.Init(nonces)
	kCt := hera.EncKey(key)
	hera.KeySchedule(kCt)
	fmt.Println("Done")

	// FV Keystream
	fmt.Println()
	fmt.Println("Evaluate FV keystream by Hera")
	fvKeystreams := hera.Crypt()
	for i := 0; i < 16; i++ {
		fvKeystreams[i] = fvEvaluator.SlotsToCoeffs(fvKeystreams[i])
		fvEvaluator.ModSwitchMany(fvKeystreams[i], fvKeystreams[i], fvKeystreams[i].Level())
	}
	fmt.Println("Done")

	// Encrypt and mod switch to the lowest level
	fmt.Println()
	fmt.Println("Encryption and rescaling to level 0...")
	ciphertexts := make([]*ckks_fv.Ciphertext, 16)
	for s := 0; s < 16; s++ {
		ciphertexts[s] = ckks_fv.NewCiphertextFVLvl(params, 1, 0)
		ciphertexts[s].Value()[0] = plaintexts[s].Value()[0].CopyNew()
		fvEvaluator.Sub(ciphertexts[s], fvKeystreams[s], ciphertexts[s])
		fvEvaluator.TransformToNTT(ciphertexts[s], ciphertexts[s])
		ciphertexts[s].SetScale(float64(params.Qi()[0]) / float64(params.T()) * messageScaling)
	}

	fmt.Println("Done")

	// Half-Bootstrap the ciphertext (homomorphic evaluation of ModRaise -> SubSum -> CtS -> EvalMod)
	// It takes a ciphertext at level 0 (if not at level 0, then it will reduce it to level 0)
	// and returns a ciphertext at level MaxLevel - k, where k is the depth of the bootstrapping circuit.
	// Difference from the bootstrapping is that the last StC is missing.
	// CAUTION: the scale of the ciphertext MUST be equal (or very close) to params.Scale
	// To equalize the scale, the function evaluator.SetScale(ciphertext, parameters.Scale) can be used at the expense of one level.
	fmt.Println()
	fmt.Println("Half-Bootstrapping...")

	if fullCoeffs {
		for s := 0; s < 16; s++ {
			ctBoot0, ctBoot1 := hbtp.HalfBoot(ciphertexts[s])
			fmt.Println("Done")

			valuesWant0 := make([]complex128, params.Slots())
			valuesWant1 := make([]complex128, params.Slots())
			for i := 0; i < params.Slots(); i++ {
				valuesWant0[i] = complex(data[s][i], 0)
				valuesWant1[i] = complex(data[s][i+params.N()/2], 0)
			}

			fmt.Println()
			fmt.Println("Precision of ciphertext vs. HalfBoot(ciphertext)")
			printDebug(params, ctBoot0, valuesWant0, ckksDecryptor, ckksEncoder)
			printDebug(params, ctBoot1, valuesWant1, ckksDecryptor, ckksEncoder)
		}
	} else {
		for s := 0; s < 16; s++ {
			ctBoot0, ctBoot1 := hbtp.HalfBoot(ciphertexts[s])
			fmt.Println("Done")

			valuesWant := make([]complex128, params.Slots())
			for i := 0; i < params.Slots(); i++ {
				valuesWant[i] = complex(data[s][i], 0)
			}

			ctBoot := ckksEvaluator.RotateNew(ctBoot1, params.Slots()/2)
			ckksEvaluator.Add(ctBoot, ctBoot0, ctBoot)

			fmt.Println()
			fmt.Println("Precision of ciphertext vs. HalfBoot(ciphertext)")
			printDebug(params, ctBoot, valuesWant, ckksDecryptor, ckksEncoder)
		}
	}
	fmt.Println()
}

func fvNoiseBudget() {
	params := ckks_fv.DefaultFVParams[1]
	encoder := ckks_fv.NewMFVEncoder(params)

	kgen := ckks_fv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	encryptor := ckks_fv.NewMFVEncryptorFromPk(params, pk)
	decryptor := ckks_fv.NewMFVDecryptor(params, sk)
	noiseEstimator := ckks_fv.NewMFVNoiseEstimator(params, sk)

	rlk := kgen.GenRelinearizationKey(sk)
	rotIndex := make([]uint64, params.LogN())
	for i := 0; i < params.LogN()-1; i++ {
		rotIndex[i] = params.GaloisElementForColumnRotationBy(1 << i)
	}
	rotIndex[params.LogN()-1] = params.GaloisElementForRowRotation()
	rotkeys := kgen.GenRotationKeys(rotIndex, sk)
	evaluator := ckks_fv.NewMFVEvaluator(params, ckks_fv.EvaluationKey{Rlk: rlk, Rtks: rotkeys}, nil)

	N := params.N()
	data1 := make([]uint64, N)
	data2 := make([]uint64, N)
	for i := 0; i < N; i++ {
		data1[i] = uint64(i)
		data2[i] = params.T() - uint64(i+1)
	}

	plaintext1 := ckks_fv.NewPlaintextFV(params)
	plaintext2 := ckks_fv.NewPlaintextFV(params)
	encoder.EncodeUint(data1, plaintext1)
	encoder.EncodeUint(data2, plaintext2)

	ciphertext1 := encryptor.EncryptNew(plaintext1)
	evaluator.ModSwitch(ciphertext1, ciphertext1)

	var budget int
	budget = noiseEstimator.InvariantNoiseBudget(ciphertext1)
	fmt.Printf("Noise budget: %d bits\n", budget)
	printDec(ciphertext1, 16, decryptor, encoder)

	ciphertext1 = evaluator.MulNew(ciphertext1, ciphertext1)
	evaluator.Relinearize(ciphertext1, ciphertext1)
	budget = noiseEstimator.InvariantNoiseBudget(ciphertext1)
	fmt.Printf("Noise budget: %d bits\n", budget)
	printDec(ciphertext1, 16, decryptor, encoder)
	evaluator.ModSwitch(ciphertext1, ciphertext1)

	ciphertext1 = evaluator.MulNew(ciphertext1, ciphertext1)
	evaluator.Relinearize(ciphertext1, ciphertext1)
	budget = noiseEstimator.InvariantNoiseBudget(ciphertext1)
	fmt.Printf("Noise budget: %d bits\n", budget)
	printDec(ciphertext1, 16, decryptor, encoder)

	ciphertext1 = evaluator.MulNew(ciphertext1, ciphertext1)
	evaluator.Relinearize(ciphertext1, ciphertext1)
	budget = noiseEstimator.InvariantNoiseBudget(ciphertext1)
	fmt.Printf("Noise budget: %d bits\n", budget)
	printDec(ciphertext1, 16, decryptor, encoder)

	ciphertext1 = evaluator.MulNew(ciphertext1, ciphertext1)
	evaluator.Relinearize(ciphertext1, ciphertext1)
	budget = noiseEstimator.InvariantNoiseBudget(ciphertext1)
	fmt.Printf("Noise budget: %d bits\n", budget)
	printDec(ciphertext1, 16, decryptor, encoder)

	ciphertext1 = evaluator.MulNew(ciphertext1, ciphertext1)
	evaluator.Relinearize(ciphertext1, ciphertext1)
	budget = noiseEstimator.InvariantNoiseBudget(ciphertext1)
	fmt.Printf("Noise budget: %d bits\n", budget)
	printDec(ciphertext1, 16, decryptor, encoder)
	fmt.Println()

}

func smallBatchMFV() {
	params := ckks_fv.DefaultFVParams[8]
	logFVSlots := params.LogFVSlots()
	FVSlots := params.FVSlots()
	fmt.Printf("params.logFVSlots: %d\n", logFVSlots)
	encoder := ckks_fv.NewMFVEncoder(params)

	kgen := ckks_fv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	encryptor := ckks_fv.NewMFVEncryptorFromPk(params, pk)
	decryptor := ckks_fv.NewMFVDecryptor(params, sk)

	rlk := kgen.GenRelinearizationKey(sk)
	pDcds := encoder.GenSlotToCoeffMatFV()
	rotations := kgen.GenRotationIndexesForSlotsToCoeffsMat(pDcds)
	rotkeys := kgen.GenRotationKeysForRotations(rotations, true, sk)

	evaluator := ckks_fv.NewMFVEvaluator(params, ckks_fv.EvaluationKey{Rlk: rlk, Rtks: rotkeys}, pDcds)

	data1 := make([]uint64, FVSlots)
	data2 := make([]uint64, FVSlots)
	for i := range data1 {
		data1[i] = uint64(i)
		data2[i] = uint64(2 * i)
	}

	plaintext1 := ckks_fv.NewPlaintextFV(params)
	plaintext2 := ckks_fv.NewPlaintextFV(params)
	encoder.EncodeUintSmall(data1, plaintext1)
	encoder.EncodeUintSmall(data2, plaintext2)

	ciphertext1 := encryptor.EncryptNew(plaintext1)
	ciphertext2 := encryptor.EncryptNew(plaintext2)

	evaluator.ModSwitch(ciphertext1, ciphertext1)
	evaluator.ModSwitch(ciphertext1, ciphertext1)
	evaluator.ModSwitchMany(ciphertext2, ciphertext2, 2)

	var ciphertext, tmp1, tmp2 *ckks_fv.Ciphertext
	var decrypted *ckks_fv.Plaintext
	var rot1, rot2, level int
	decoded := make([]uint64, FVSlots)
	ptRt := ckks_fv.NewPlaintextRingT(params)

	// Test Add
	fmt.Println("Test Add")
	ciphertext = evaluator.AddNew(ciphertext1, ciphertext2)
	decrypted = decryptor.DecryptNew(ciphertext)
	encoder.DecodeUintSmall(decrypted, decoded)
	for i := 0; i < FVSlots; i++ {
		sol := data1[i] + data2[i]
		fmt.Printf("decoded[%d]: %d (== %d)\n", i, decoded[i], sol)
	}
	fmt.Println()

	// Test Mul + Relin
	fmt.Println("Test Mul (+ Relin)")
	fmt.Println("1. Multiply by PlaintextMul")
	plaintextMul := ckks_fv.NewPlaintextMulLvl(params, ciphertext2.Level())
	encoder.EncodeUintMulSmall(data2, plaintextMul)
	ciphertext = evaluator.MulNew(ciphertext1, plaintextMul)
	evaluator.Relinearize(ciphertext, ciphertext)
	decrypted = decryptor.DecryptNew(ciphertext)
	decoded = encoder.DecodeUintSmallNew(decrypted)
	for i := 0; i < FVSlots; i++ {
		sol := (data1[i] * data2[i]) % params.T()
		fmt.Printf("decoded[%d]: %d (== %d)\n", i, decoded[i], sol)
	}
	fmt.Println()
	fmt.Println("2. Multiply By PlaintextRingT")
	plaintextRingT := ckks_fv.NewPlaintextRingT(params)
	encoder.EncodeUintRingTSmall(data2, plaintextRingT)
	ciphertext = evaluator.MulNew(ciphertext1, plaintextRingT)
	evaluator.Relinearize(ciphertext, ciphertext)
	decrypted = decryptor.DecryptNew(ciphertext)
	decoded = encoder.DecodeUintSmallNew(decrypted)
	for i := 0; i < FVSlots; i++ {
		sol := (data1[i] * data2[i]) % params.T()
		fmt.Printf("decoded[%d]: %d (== %d)\n", i, decoded[i], sol)
	}
	fmt.Println()
	fmt.Println("3. Multiply by Plaintext")
	plaintext2 = decryptor.DecryptNew(ciphertext2)
	ciphertext = evaluator.MulNew(ciphertext1, plaintext2)
	evaluator.Relinearize(ciphertext, ciphertext)
	decrypted = decryptor.DecryptNew(ciphertext)
	encoder.DecodeUintSmall(decrypted, decoded)
	for i := 0; i < FVSlots; i++ {
		sol := (data1[i] * data2[i]) % params.T()
		fmt.Printf("decoded[%d]: %d (== %d)\n", i, decoded[i], sol)
	}
	fmt.Println()
	fmt.Println("4. Multiply by Ciphertext")
	ciphertext = evaluator.MulNew(ciphertext1, ciphertext2)
	evaluator.Relinearize(ciphertext, ciphertext)
	decrypted = decryptor.DecryptNew(ciphertext)
	encoder.DecodeUintSmall(decrypted, decoded)
	for i := 0; i < FVSlots; i++ {
		sol := (data1[i] * data2[i]) % params.T()
		fmt.Printf("decoded[%d]: %d (== %d)\n", i, decoded[i], sol)
	}
	fmt.Println()

	_, _, _, _ = tmp1, tmp2, rot1, rot2
	// Test RotateColumns
	/*
		fmt.Println("Test RotateColumns")
		rot1 = 6
		rot2 = 1
		tmp1 = ckks_fv.NewCiphertextFVLvl(params, 1, ciphertext1.Level())
		tmp2 = ckks_fv.NewCiphertextFVLvl(params, 1, ciphertext2.Level())
		evaluator.RotateColumns(ciphertext1, rot1, tmp1)
		evaluator.RotateColumns(ciphertext2, rot2, tmp2)
		ciphertext = evaluator.AddNew(tmp1, tmp2)

		decrypted = decryptor.DecryptNew(ciphertext)
		encoder.DecodeUintSmall(decrypted, decoded)

		for i := 0; i < FVSlots/2; i++ {
			sol := data1[(i+rot1)%(FVSlots/2)] + data2[(i+rot2)%(FVSlots/2)]
			fmt.Printf("decoded[%d]: %d (== %d)\n", i, decoded[i], sol)
		}
		fmt.Println()

		for i := FVSlots / 2; i < FVSlots; i++ {
			sol := data1[FVSlots/2+(i+rot1)%(FVSlots/2)] + data2[FVSlots/2+(i+rot2)%(FVSlots/2)]
			fmt.Printf("decoded[%d]: %d (== %d)\n", i, decoded[i], sol)
		}
		fmt.Println()
	*/
	// Test RotateRows
	fmt.Println("Test RotateRows")
	evaluator.RotateRows(ciphertext1, ciphertext)

	decrypted = decryptor.DecryptNew(ciphertext)
	encoder.DecodeUintSmall(decrypted, decoded)

	for i := 0; i < FVSlots/2; i++ {
		sol := data1[i+FVSlots/2]
		fmt.Printf("decoded[%d]: %d (== %d)\n", i, decoded[i], sol)
	}
	fmt.Println()

	for i := FVSlots / 2; i < FVSlots; i++ {
		sol := data1[i-FVSlots/2]
		fmt.Printf("decoded[%d]: %d (== %d)\n", i, decoded[i], sol)
	}
	fmt.Println()

	// Test Linear Transform
	fmt.Println("Test Linear Transform")
	mat := make(map[int][]uint64)
	mat[0] = make([]uint64, FVSlots)
	for i := 0; i < FVSlots; i++ {
		mat[0][i] = uint64(i)
	}

	mat[1] = make([]uint64, FVSlots)
	for i := 0; i < FVSlots; i++ {
		mat[1][i] = 2
	}

	mat[6] = make([]uint64, FVSlots)
	for i := 0; i < FVSlots; i++ {
		mat[6][i] = 1
	}

	level = ciphertext1.Level()
	ptDiagMatrixT := encoder.EncodeDiagMatrixT(level, mat, 16, logFVSlots)
	fmt.Printf("patDiagMatrixT.N1: %d\n", ptDiagMatrixT.N1)
	res := evaluator.LinearTransform(ciphertext1, ptDiagMatrixT)[0]
	decrypted = decryptor.DecryptNew(res)
	encoder.DecodeUintSmall(decrypted, decoded)

	l := FVSlots / 2
	A := make([][]uint64, l)
	B := make([][]uint64, l)
	for i := 0; i < l; i++ {
		A[i] = make([]uint64, l)
		B[i] = make([]uint64, l)
	}

	for k := range mat {
		for i := 0; i < l; i++ {
			A[i][(i+k)%l] = mat[k][i]
		}
		for i := l; i < FVSlots; i++ {
			B[i-l][(i+k)%l] = mat[k][i]
		}
	}

	for i := 0; i < l; i++ {
		fmt.Printf("[ ")
		for j := 0; j < l; j++ {
			fmt.Printf("%3d ", A[i][j])
		}
		fmt.Printf("]")
		if i == l/2-1 {
			fmt.Printf("   |/  ")
		} else if i == l/2 {
			fmt.Printf("  /|   ")
		} else {
			fmt.Printf("       ")
		}
		fmt.Printf("[ %3d ]", data1[i])

		if i == l/2-1 || i == l/2 {
			fmt.Printf("  ---  ")
		} else {
			fmt.Printf("       ")
		}
		fmt.Printf("[ %3d ]\n", decoded[i])
	}
	fmt.Println()

	for i := 0; i < l; i++ {
		fmt.Printf("[ ")
		for j := 0; j < l; j++ {
			fmt.Printf("%3d ", B[i][j])
		}
		fmt.Printf("]")
		if i == l/2-1 {
			fmt.Printf("   |/  ")
		} else if i == l/2 {
			fmt.Printf("  /|   ")
		} else {
			fmt.Printf("       ")
		}
		fmt.Printf("[ %3d ]", data1[i+l])

		if i == l/2-1 || i == l/2 {
			fmt.Printf("  ---  ")
		} else {
			fmt.Printf("       ")
		}
		fmt.Printf("[ %3d ]\n", decoded[i+l])
	}
	fmt.Println()

	// Test SlotsToCoeffs
	fmt.Println("Test SlotsToCoeffs")
	ciphertext = evaluator.SlotsToCoeffs(ciphertext1)
	decrypted = decryptor.DecryptNew(ciphertext)
	encoder.DecodeRingT(decrypted, ptRt)
	for i := 0; i < params.N(); i++ {
		j := utils.BitReverse64(uint64(i), uint64(params.LogN()))
		coeffi := ptRt.Value()[0].Coeffs[0][j]
		fmt.Printf("[%d] decrypted[%d]: %d\n", i, j, coeffi)
	}
	fmt.Println()
}

func main() {
	var input string
	var index int
	var err error

	choice := "Choose one of 0, 1, 2, 3, 4.\n"
	for true {
		fmt.Println("Choose an example:")
		fmt.Println("  (1): RtF Framework")
		fmt.Println("  (2): MFV Noise Estimate")
		fmt.Println("  (3): Small MFV Batching")
		fmt.Println("  (4): HEra")
		fmt.Println("To exit, enter 0.")
		fmt.Print("Input: ")
		fmt.Scanln(&input)

		if index, err = strconv.Atoi(input); err == nil {
			switch index {
			case 0:
				return
			case 1:
				fmt.Println()
				RtF()
			case 2:
				fmt.Println()
				fvNoiseBudget()
			case 3:
				fmt.Println()
				smallBatchMFV()
			case 4:
				fmt.Println()
				testHera()
			default:
				fmt.Println(choice)
			}
		} else {
			fmt.Println(choice)
		}
	}
}
