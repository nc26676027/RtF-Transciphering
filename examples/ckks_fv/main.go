package main

import (
	"fmt"
	"math"
	"strconv"

	"github.com/ldsec/lattigo/v2/ckks_fv"
	"github.com/ldsec/lattigo/v2/utils"
)

func printDebug(params *ckks_fv.Parameters, ciphertext *ckks_fv.Ciphertext, valuesWant []complex128, decryptor ckks_fv.CKKSDecryptor, encoder ckks_fv.Encoder) (valuesTest []complex128) {

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

func transciphering() {
	fmt.Println("==== Transciphering ====")
	// Set parameters
	params := ckks_fv.DefaultParams[ckks_fv.PN15QP880]
	params.SetT(0xffd0001) // 28-bit
	ckksScale := float64(params.T()) / (1 << 3)
	params.SetScale(ckksScale)

	fmt.Println()
	fmt.Printf("CKKS parameters: logN = %d, logSlots = %d, logQP = %d, levels = %d, scale= 2^%f, sigma = %f \n", params.LogN(), params.LogSlots(), params.LogQP(), params.Levels(), math.Log2(params.Scale()), params.Sigma())

	qi := params.Qi()

	// Key generation
	kgen := ckks_fv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairSparse(64)
	rlk := kgen.GenRelinearizationKey(sk)

	encoder := ckks_fv.NewEncoder(params)
	fvEncryptor := ckks_fv.NewFVEncryptorFromPk(params, pk)
	fvEvaluator := ckks_fv.NewFVEvaluator(params, ckks_fv.EvaluationKey{})
	ckksEvaluator := ckks_fv.NewCKKSEvaluator(params, ckks_fv.EvaluationKey{Rlk: rlk})
	ckksDecryptor := ckks_fv.NewCKKSDecryptor(params, sk)

	// Set data
	ckksData := make([]complex128, params.Slots())
	for i := range ckksData {
		ckksData[i] = complex(utils.RandFloat64(0, 1), 0)
	}

	// CKKS Plaintext to FV Plaintext
	plainCKKSRingT := encoder.EncodeComplexRingTNew(ckksData, params.LogSlots())
	plainCKKS := ckks_fv.NewPlaintextFV(params)
	encoder.FVScaleUp(plainCKKSRingT, plainCKKS)

	// FV Encryption
	cipherFV := fvEncryptor.EncryptNew(plainCKKS)

	// Transform to NTT
	fvEvaluator.TransformToNTT(cipherFV, cipherFV)

	// Rescale
	ckksEvaluator.RescaleMany(cipherFV, cipherFV.Level(), cipherFV)
	cipherFV.SetScale(ckksScale * float64(qi[0]) / float64(params.T()))

	// CKKS ciphertext precision
	printDebug(params, cipherFV, ckksData, ckksDecryptor, encoder)
}

func transcipheringWithBoot() {
	fmt.Println("==== Transciphering with Bootstrapping ====")

	var err error
	var btp *ckks_fv.Bootstrapper
	var kgen ckks_fv.KeyGenerator
	var encoder ckks_fv.Encoder
	var sk *ckks_fv.SecretKey
	var pk *ckks_fv.PublicKey
	var fvEncryptor ckks_fv.FVEncryptor
	var ckksDecryptor ckks_fv.CKKSDecryptor
	var fvEvaluator ckks_fv.FVEvaluator
	var ckksEvaluator ckks_fv.CKKSEvaluator

	// Bootstrapping parameters
	// Four sets of parameters (index 0 to 3) ensuring 128 bit of security
	// are available in github.com/ldsec/lattigo/v2/ckks/bootstrap_params
	// LogSlots is hardcoded to 15 in the parameters, but can be changed from 1 to 15.
	// When changing logSlots make sure that the number of levels allocated to CtS and StC is
	// smaller or equal to logSlots.

	btpParams := ckks_fv.DefaultBootstrapParams[0]
	params, err := btpParams.Params()
	if err != nil {
		panic(err)
	}

	ckksScale := float64(params.T()) / (1 << 10)
	params.SetScale(ckksScale)

	fmt.Println()
	fmt.Printf("CKKS parameters: logN = %d, logSlots = %d, h = %d, logQP = %d, levels = %d, scale= 2^%f, sigma = %f \n", params.LogN(), params.LogSlots(), btpParams.H, params.LogQP(), params.Levels(), math.Log2(params.Scale()), params.Sigma())

	// Scheme context and keys
	kgen = ckks_fv.NewKeyGenerator(params)

	sk, pk = kgen.GenKeyPairSparse(btpParams.H)

	encoder = ckks_fv.NewEncoder(params)
	fvEncryptor = ckks_fv.NewFVEncryptorFromPk(params, pk)
	fvEvaluator = ckks_fv.NewFVEvaluator(params, ckks_fv.EvaluationKey{})
	ckksEvaluator = ckks_fv.NewCKKSEvaluator(params, ckks_fv.EvaluationKey{})
	ckksDecryptor = ckks_fv.NewCKKSDecryptor(params, sk)

	fmt.Println()
	fmt.Println("Generating bootstrapping keys...")
	rotations := kgen.GenRotationIndexesForBootstrapping(params.LogSlots(), btpParams)
	rotkeys := kgen.GenRotationKeysForRotations(rotations, true, sk)
	rlk := kgen.GenRelinearizationKey(sk)
	btpKey := ckks_fv.BootstrappingKey{Rlk: rlk, Rtks: rotkeys}
	if btp, err = ckks_fv.NewBootstrapper(params, btpParams, btpKey); err != nil {
		panic(err)
	}
	fmt.Println("Done")

	// Generate a random plaintext
	ckksData := make([]complex128, params.Slots())
	for i := range ckksData {
		ckksData[i] = utils.RandComplex128(-1, 1)
	}

	plainCKKSRingT := encoder.EncodeComplexRingTNew(ckksData, params.LogSlots())
	plainCKKS := ckks_fv.NewPlaintextFV(params)
	encoder.FVScaleUp(plainCKKSRingT, plainCKKS)

	// FV Encryption
	cipherFV := fvEncryptor.EncryptNew(plainCKKS)

	// Transform to NTT
	fvEvaluator.TransformToNTT(cipherFV, cipherFV)

	// Rescale
	ckksEvaluator.RescaleMany(cipherFV, cipherFV.Level(), cipherFV)
	cipherFV.SetScale(ckksScale * float64(params.Qi()[0]) / float64(params.T()))

	// CKKS ciphertext precision
	printDebug(params, cipherFV, ckksData, ckksDecryptor, encoder)

	// Bootstrapping
	fmt.Println()
	fmt.Println("Bootstrapping...")
	cipherBoot := btp.Bootstrapp(cipherFV)
	fmt.Println("Done")

	// Decrypt, print and compare with the plaintext values
	fmt.Println()
	fmt.Println("Precision of ciphertext vs. Bootstrapp(ciphertext)")
	printDebug(params, cipherBoot, ckksData, ckksDecryptor, encoder)
}

func RtF() {
	fmt.Println("==== RtF Framework ====")
	var err error

	var hbtp *ckks_fv.HalfBootstrapper
	var kgen ckks_fv.KeyGenerator
	var encoder ckks_fv.Encoder
	var sk *ckks_fv.SecretKey
	var pk *ckks_fv.PublicKey
	var fvEncryptor ckks_fv.FVEncryptor
	var ckksDecryptor ckks_fv.CKKSDecryptor
	var fvEvaluator ckks_fv.FVEvaluator
	var ckksEvaluator ckks_fv.CKKSEvaluator
	var plainCKKSRingT *ckks_fv.PlaintextRingT
	var plaintext *ckks_fv.Plaintext

	// Half-Bootstrapping parameters
	// Four sets of parameters (index 0 to 3) ensuring 128 bit of security
	// are available in github.com/ldsec/lattigo/v2/ckks/halfboot_params
	// LogSlots is hardcoded to 15 in the parameters, but can be changed from 1 to 15.
	// When changing logSlots make sure that the number of levels allocated to CtS is
	// smaller or equal to logSlots.

	hbtpParams := ckks_fv.DefaultHalfBootParams[2]
	params, err := hbtpParams.Params()
	if err != nil {
		panic(err)
	}

	fvParams := ckks_fv.DefaultParams[9]
	if params.Qi()[0] != fvParams.Qi()[0] {
		panic("Q0 does not match")
	}
	fvParams.SetT(params.T())

	fmt.Println()
	fmt.Printf("CKKS parameters: logN = %d, logSlots = %d, h = %d, logQP = %d, levels = %d, scale= 2^%f, sigma = %f \n", params.LogN(), params.LogSlots(), hbtpParams.H, params.LogQP(), params.Levels(), math.Log2(params.Scale()), params.Sigma())

	// Scheme context and keys
	kgen = ckks_fv.NewKeyGenerator(params)

	sk, pk = kgen.GenKeyPairSparse(hbtpParams.H)

	encoder = ckks_fv.NewEncoder(params)
	fvEncryptor = ckks_fv.NewFVEncryptorFromPk(params, pk)
	ckksDecryptor = ckks_fv.NewCKKSDecryptor(params, sk)

	fmt.Println()
	fmt.Println("Generating half-bootstrapping keys...")
	rotations := kgen.GenRotationIndexesForHalfBoot(params.LogSlots(), hbtpParams)
	rotkeys := kgen.GenRotationKeysForRotations(rotations, true, sk)
	rlk := kgen.GenRelinearizationKey(sk)
	hbtpKey := ckks_fv.BootstrappingKey{Rlk: rlk, Rtks: rotkeys}

	if hbtp, err = ckks_fv.NewHalfBootstrapper(params, hbtpParams, hbtpKey); err != nil {
		panic(err)
	}
	fmt.Println("Done")
	fvEvaluator = ckks_fv.NewFVEvaluator(params, ckks_fv.EvaluationKey{})
	ckksEvaluator = ckks_fv.NewCKKSEvaluator(params, ckks_fv.EvaluationKey{Rlk: rlk, Rtks: rotkeys})

	// Encode float data added by keystream to plaintext coefficients
	fmt.Println()
	fmt.Println("Encode random numbers on coefficients...")
	var data []float64
	var keystream []uint64
	coeffs := make([]float64, params.N())

	fullCoeffs := false
	fullCoeffs = fullCoeffs && (params.LogN() == params.LogSlots()+1)
	if fullCoeffs {
		data = make([]float64, params.N())
		keystream = make([]uint64, params.N())
		for i := 0; i < params.N(); i++ {
			data[i] = utils.RandFloat64(-1, 1)
			keystream[i] = utils.RandUint64() % params.T()
		}

		for i := 0; i < params.N()/2; i++ {
			j := utils.BitReverse64(uint64(i), uint64(params.LogN()-1))
			coeffs[j] = data[i]
			coeffs[uint64(params.N()/2)+j] = data[i+params.N()/2]
		}

		plainCKKSRingT = encoder.EncodeCoeffsRingTNew(coeffs, float64(params.T()/(1<<11)))
		poly := plainCKKSRingT.Value()[0]
		for i := 0; i < params.N()/2; i++ {
			j := utils.BitReverse64(uint64(i), uint64(params.LogN()-1))
			poly.Coeffs[0][j] = (poly.Coeffs[0][j] + keystream[i]) % params.T()
			j = j + uint64(params.N()/2)
			poly.Coeffs[0][j] = (poly.Coeffs[0][j] + keystream[i+params.N()/2]) % params.T()
		}
	} else {
		data = make([]float64, params.Slots())
		keystream = make([]uint64, params.Slots())
		for i := 0; i < params.Slots(); i++ {
			data[i] = utils.RandFloat64(-1, 1)
			keystream[i] = utils.RandUint64() % params.T()
		}

		for i := 0; i < params.Slots(); i++ {
			j := utils.BitReverse64(uint64(i), uint64(params.LogN()-1))
			coeffs[j] = data[i]
		}

		plainCKKSRingT = encoder.EncodeCoeffsRingTNew(coeffs, float64(params.T()/(1<<11)))
		poly := plainCKKSRingT.Value()[0]
		for i := 0; i < params.Slots(); i++ {
			j := utils.BitReverse64(uint64(i), uint64(params.LogN()-1))
			poly.Coeffs[0][j] = (poly.Coeffs[0][j] + keystream[i]) % params.T()
		}
	}

	// plainCKKSRingT := encoder.EncodeCoeffsRingTNew(coeffs, float64(params.T())/(1<<11))
	plaintext = ckks_fv.NewPlaintextFV(params)
	encoder.FVScaleUp(plainCKKSRingT, plaintext)

	fmt.Println("Done")

	// FV Keystream
	fmt.Println()
	fmt.Println("Evaluate FV keystream")
	pKeystream := ckks_fv.NewPlaintextFV(fvParams)
	pKeystreamRingT := ckks_fv.NewPlaintextRingT(fvParams)
	if fullCoeffs {
		for i := 0; i < params.N()/2; i++ {
			j := utils.BitReverse64(uint64(i), uint64(params.LogN()-1))
			pKeystreamRingT.Value()[0].Coeffs[0][j] = keystream[i]
			pKeystreamRingT.Value()[0].Coeffs[0][j+uint64(params.N()/2)] = keystream[i+params.N()/2]
		}
	} else {
		for i := 0; i < params.Slots(); i++ {
			j := utils.BitReverse64(uint64(i), uint64(params.LogN()-1))
			pKeystreamRingT.Value()[0].Coeffs[0][j] = keystream[i]
		}
	}
	encoder.FVScaleUp(pKeystreamRingT, pKeystream)
	fvKeystream := fvEncryptor.EncryptNew(pKeystream)
	fvEvaluator.TransformToNTT(fvKeystream, fvKeystream)
	ckksEvaluator.RescaleMany(fvKeystream, fvKeystream.Level(), fvKeystream)
	fmt.Println("Done")

	// Encrypt and rescale to the lowest level
	fmt.Println()
	fmt.Println("Encryption and rescaling to level 0...")
	ciphertext := fvEncryptor.EncryptNew(plaintext)
	fvEvaluator.TransformToNTT(ciphertext, ciphertext)
	ckksEvaluator.RescaleMany(ciphertext, ciphertext.Level(), ciphertext)
	ckksEvaluator.Sub(ciphertext, fvKeystream, ciphertext)
	ciphertext.SetScale(float64(params.Qi()[0]) / (1 << 11))
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
		ctBoot0, ctBoot1 := hbtp.HalfBoot(ciphertext)
		fmt.Println("Done")

		valuesWant0 := make([]complex128, params.Slots())
		valuesWant1 := make([]complex128, params.Slots())
		for i := 0; i < params.Slots(); i++ {
			valuesWant0[i] = complex(data[i], 0)
			valuesWant1[i] = complex(data[i+params.N()/2], 0)
		}

		fmt.Println()
		fmt.Println("Precision of ciphertext vs. HalfBoot(ciphertext)")
		printDebug(params, ctBoot0, valuesWant0, ckksDecryptor, encoder)
		printDebug(params, ctBoot1, valuesWant1, ckksDecryptor, encoder)

	} else {
		ctBoot, _ := hbtp.HalfBoot(ciphertext)
		fmt.Println("Done")

		valuesWant := make([]complex128, params.Slots())
		for i := 0; i < params.Slots(); i++ {
			valuesWant[i] = complex(data[i], 0)
		}

		fmt.Println()
		fmt.Println("Precision of ciphertext vs. HalfBoot(ciphertext)")
		printDebug(params, ctBoot, valuesWant, ckksDecryptor, encoder)
	}
}

func fvLT() {
	var params *ckks_fv.Parameters
	// params = ckks_fv.DefaultParams[10] // params.N == params.Slots
	params = ckks_fv.DefaultParams[11] // params.N > params.Slots
	slots := params.Slots()

	kgen := ckks_fv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	encryptor := ckks_fv.NewFVEncryptorFromPk(params, pk)
	decryptor := ckks_fv.NewFVDecryptor(params, sk)
	encoder := ckks_fv.NewEncoder(params)

	rotations := []int{1, 2, 3}
	rotkeys := kgen.GenRotationKeysForRotations(rotations, true, sk)
	evaluator := ckks_fv.NewFVEvaluator(params, ckks_fv.EvaluationKey{Rtks: rotkeys})

	data := make([]uint64, slots)
	for i := range data {
		data[i] = uint64(i)
	}

	plaintext := ckks_fv.NewPlaintextFV(params)
	encoder.EncodeUint(data, plaintext)
	ciphertext := encryptor.EncryptNew(plaintext)

	mat := make([]map[int][]uint64, 1)
	mat[0] = make(map[int][]uint64)
	mat[0][0] = make([]uint64, slots)
	for i := 0; i < slots; i++ {
		mat[0][0][i] = 1
	}
	mat[0][1] = make([]uint64, slots)
	for i := 0; i < slots; i++ {
		mat[0][1][i] = uint64(i)
	}
	mat[0][2] = make([]uint64, slots)
	for i := 0; i < slots; i++ {
		mat[0][2][i] = 0
	}
	mat[0][3] = make([]uint64, slots)
	for i := 0; i < slots; i++ {
		mat[0][3][i] = 2
	}

	ptDiagMatrixT := encoder.EncodeDiagMatrixT(mat[0], 16.0, params.LogSlots())
	// fmt.Printf("ptDiagMatrixT.N1: %d\n", ptDiagMatrixT.N1)

	res := evaluator.LinearTransform(ciphertext, ptDiagMatrixT)[0]
	decrypted := decryptor.DecryptNew(res)
	decoded := encoder.DecodeUintNew(decrypted)

	fmt.Printf("Matrix multiplication in Zt for t = %d:\n", params.T())
	if params.Slots() < params.N() {
		A := make([][]uint64, slots)
		for i := 0; i < slots; i++ {
			A[i] = make([]uint64, slots)
		}

		for k := range mat[0] {
			for i := 0; i < slots; i++ {
				A[i][(i+k)%slots] = mat[0][k][i]
			}
		}

		for i := 0; i < slots; i++ {
			fmt.Printf("[ ")
			for j := 0; j < slots; j++ {
				fmt.Printf("%3d ", A[i][j])
			}
			fmt.Printf("]")
			if i == slots/2-1 {
				fmt.Printf("   |/  ")
			} else if i == slots/2 {
				fmt.Printf("  /|   ")
			} else {
				fmt.Printf("       ")
			}
			fmt.Printf("[ %3d ]", data[i])

			if i == slots/2-1 || i == slots/2 {
				fmt.Printf("  ---  ")
			} else {
				fmt.Printf("       ")
			}
			fmt.Printf("[ %3d ]\n", decoded[i])
		}
	} else {
		l := slots / 2
		A := make([][]uint64, l)
		B := make([][]uint64, l)
		for i := 0; i < l; i++ {
			A[i] = make([]uint64, l)
			B[i] = make([]uint64, l)
		}

		for k := range mat[0] {
			for i := 0; i < l; i++ {
				A[i][(i+k)%l] = mat[0][k][i]
			}
			for i := l; i < slots; i++ {
				B[i-l][(i+k)%l] = mat[0][k][i]
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
			fmt.Printf("[ %3d ]", data[i])

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
			fmt.Printf("[ %3d ]", data[i+l])

			if i == l/2-1 || i == l/2 {
				fmt.Printf("  ---  ")
			} else {
				fmt.Printf("       ")
			}
			fmt.Printf("[ %3d ]\n", decoded[i+l])
		}
	}
}

func MultiLevelFV() {
	params := ckks_fv.DefaultFVParams[1]
	encoder := ckks_fv.NewMFVEncoder(params)

	kgen := ckks_fv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	encryptor := ckks_fv.NewMFVEncryptorFromPk(params, pk)
	decryptor := ckks_fv.NewMFVDecryptor(params, sk)

	rlk := kgen.GenRelinearizationKey(sk)
	rotIndex := make([]uint64, params.LogN())
	for i := 0; i < params.LogN()-1; i++ {
		rotIndex[i] = params.GaloisElementForColumnRotationBy(1 << i)
	}
	rotIndex[params.LogN()-1] = params.GaloisElementForRowRotation()
	rotkeys := kgen.GenRotationKeys(rotIndex, sk)
	evaluator := ckks_fv.NewMFVEvaluator(params, ckks_fv.EvaluationKey{Rlk: rlk, Rtks: rotkeys})

	N := params.N()
	data1 := make([]uint64, N)
	data2 := make([]uint64, N)
	for i := 0; i < N; i++ {
		data1[i] = uint64(2*i + 1)
		data2[i] = params.T() - uint64(i+1)
	}
	innerSum1 := uint64(0)
	innerSum2 := uint64(0)
	for i := 0; i < N; i++ {
		innerSum1 = (innerSum1 + data1[i]) % params.T()
		innerSum2 = (innerSum2 + data2[i]) % params.T()
	}

	plaintext1 := ckks_fv.NewPlaintextFV(params)
	plaintext2 := ckks_fv.NewPlaintextFV(params)
	encoder.EncodeUint(data1, plaintext1)
	encoder.EncodeUint(data2, plaintext2)

	ciphertext1 := encryptor.EncryptNew(plaintext1)
	ciphertext2 := encryptor.EncryptNew(plaintext2)

	var ciphertext *ckks_fv.Ciphertext
	ptMul := ckks_fv.NewPlaintextMul(params)
	ptRt := ckks_fv.NewPlaintextRingT(params)
	numPrint := 16

	evaluator.ModSwitchMany(ciphertext1, ciphertext1, 2)
	evaluator.ModSwitchMany(ciphertext2, ciphertext2, 2)

	fmt.Println()
	fmt.Println("Test ModSwitch")
	printDec(ciphertext1, numPrint, decryptor, encoder)
	printDec(ciphertext2, numPrint, decryptor, encoder)

	fmt.Println()
	fmt.Println("Test AddNew")
	ciphertext = evaluator.AddNew(ciphertext1, ciphertext2)
	printDec(ciphertext, numPrint, decryptor, encoder)

	fmt.Println()
	fmt.Println("Test AddNoModNew")
	ciphertext = evaluator.AddNoModNew(ciphertext1, ciphertext2)
	printDec(ciphertext, numPrint, decryptor, encoder)

	fmt.Println()
	fmt.Println("Test SubNew")
	ciphertext = evaluator.SubNew(ciphertext1, ciphertext2)
	printDec(ciphertext, numPrint, decryptor, encoder)

	fmt.Println()
	fmt.Println("Test SubNoModNew")
	ciphertext = evaluator.SubNoModNew(ciphertext1, ciphertext2)
	printDec(ciphertext, numPrint, decryptor, encoder)

	fmt.Println()
	fmt.Println("Test NegNew")
	ciphertext = evaluator.NegNew(ciphertext1)
	printDec(ciphertext, numPrint, decryptor, encoder)

	fmt.Println()
	fmt.Println("Test ReduceNew")
	ciphertext = evaluator.AddNoModNew(ciphertext1, ciphertext2)
	ciphertext = evaluator.ReduceNew(ciphertext)
	printDec(ciphertext, numPrint, decryptor, encoder)

	fmt.Println()
	fmt.Println("Test MulScalarNew")
	ciphertext = evaluator.MulScalarNew(ciphertext1, 2)
	printDec(ciphertext, numPrint, decryptor, encoder)
	ciphertext = evaluator.MulScalarNew(ciphertext2, params.T()-1)
	printDec(ciphertext, numPrint, decryptor, encoder)

	fmt.Println()
	fmt.Println("Test MulNew")
	fmt.Println("1. PlaintextMul")
	encoder.EncodeUintMul(data2, ptMul)
	ciphertext = evaluator.MulNew(ciphertext1, ptMul)
	printDec(ciphertext, numPrint, decryptor, encoder)

	fmt.Println("2. PlaintextRingT")
	encoder.EncodeUintRingT(data2, ptRt)
	ciphertext = evaluator.MulNew(ciphertext1, ptRt)
	printDec(ciphertext, numPrint, decryptor, encoder)

	fmt.Println("3. Plaintext")
	plaintext2 = decryptor.DecryptNew(ciphertext2)
	ciphertext = evaluator.MulNew(ciphertext1, plaintext2)
	printDec(ciphertext, numPrint, decryptor, encoder)

	fmt.Println("4. Ciphertext")
	ciphertext = evaluator.MulNew(ciphertext1, ciphertext2)
	printDec(ciphertext, numPrint, decryptor, encoder)

	ciphertext = evaluator.MulNew(ciphertext1, ciphertext1)
	ciphertext = evaluator.MulNew(ciphertext, ciphertext)
	printDec(ciphertext, numPrint, decryptor, encoder)

	fmt.Println()
	fmt.Println("Test Relinearize New")
	ciphertext = evaluator.MulNew(ciphertext1, ciphertext2)
	ciphertext = evaluator.RelinearizeNew(ciphertext)
	printDec(ciphertext, numPrint, decryptor, encoder)

	fmt.Println()
	fmt.Println("Test RotateColumnsNew")
	ciphertext = evaluator.RotateColumnsNew(ciphertext1, 2)
	printDec(ciphertext, numPrint, decryptor, encoder)

	fmt.Println()
	fmt.Println("Test RotateRowsNew")
	ciphertext = evaluator.RotateRowsNew(ciphertext1)
	printDec(ciphertext, numPrint, decryptor, encoder)

	fmt.Println()
	fmt.Println("Test InnerSum")
	evaluator.InnerSum(ciphertext1, ciphertext)
	fmt.Printf("InnerSum1: %d\n", innerSum1)
	printDec(ciphertext, numPrint, decryptor, encoder)

	evaluator.InnerSum(ciphertext2, ciphertext)
	fmt.Printf("InnerSum2: %d\n", innerSum2)
	printDec(ciphertext, numPrint, decryptor, encoder)

}

func printDec(ct0 *ckks_fv.Ciphertext, numPrint int, decryptor ckks_fv.MFVDecryptor, encoder ckks_fv.MFVEncoder) {
	decrypted := decryptor.DecryptNew(ct0)
	decoded := encoder.DecodeUintNew(decrypted)
	fmt.Println("  Result:")
	for i := 0; i < numPrint; i++ {
		fmt.Printf("    res[%d]: %d\n", i, decoded[i])
	}
}

func mfvLT() {
	var params *ckks_fv.Parameters
	params = ckks_fv.DefaultParams[10] // params.N == params.Slots
	// params = ckks_fv.DefaultParams[11] // params.N > params.Slots
	slots := params.Slots()

	kgen := ckks_fv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	encryptor := ckks_fv.NewMFVEncryptorFromPk(params, pk)
	decryptor := ckks_fv.NewMFVDecryptor(params, sk)
	encoder := ckks_fv.NewMFVEncoder(params)

	rotations := []int{1, 2, 3}
	rotkeys := kgen.GenRotationKeysForRotations(rotations, true, sk)
	evaluator := ckks_fv.NewMFVEvaluator(params, ckks_fv.EvaluationKey{Rtks: rotkeys})

	data := make([]uint64, slots)
	for i := range data {
		data[i] = uint64(i)
	}

	plaintext := ckks_fv.NewPlaintextFV(params)
	encoder.EncodeUint(data, plaintext)
	ciphertext := encryptor.EncryptNew(plaintext)

	mat := make([]map[int][]uint64, 1)
	mat[0] = make(map[int][]uint64)
	mat[0][0] = make([]uint64, slots)
	for i := 0; i < slots; i++ {
		mat[0][0][i] = 1
	}
	mat[0][1] = make([]uint64, slots)
	for i := 0; i < slots; i++ {
		mat[0][1][i] = uint64(i)
	}
	mat[0][2] = make([]uint64, slots)
	for i := 0; i < slots; i++ {
		mat[0][2][i] = 0
	}
	mat[0][3] = make([]uint64, slots)
	for i := 0; i < slots; i++ {
		mat[0][3][i] = 2
	}

	evaluator.ModSwitchMany(ciphertext, ciphertext, 2)
	level := ciphertext.Level()
	ptDiagMatrixT := encoder.EncodeDiagMatrixT(level, mat[0], 16.0, params.LogSlots())
	// fmt.Printf("ptDiagMatrixT.N1: %d\n", ptDiagMatrixT.N1)

	res := evaluator.LinearTransform(ciphertext, ptDiagMatrixT)[0]
	decrypted := decryptor.DecryptNew(res)
	decoded := encoder.DecodeUintNew(decrypted)

	fmt.Printf("Matrix multiplication in Zt for t = %d:\n", params.T())
	if params.Slots() < params.N() {
		A := make([][]uint64, slots)
		for i := 0; i < slots; i++ {
			A[i] = make([]uint64, slots)
		}

		for k := range mat[0] {
			for i := 0; i < slots; i++ {
				A[i][(i+k)%slots] = mat[0][k][i]
			}
		}

		for i := 0; i < slots; i++ {
			fmt.Printf("[ ")
			for j := 0; j < slots; j++ {
				fmt.Printf("%3d ", A[i][j])
			}
			fmt.Printf("]")
			if i == slots/2-1 {
				fmt.Printf("   |/  ")
			} else if i == slots/2 {
				fmt.Printf("  /|   ")
			} else {
				fmt.Printf("       ")
			}
			fmt.Printf("[ %3d ]", data[i])

			if i == slots/2-1 || i == slots/2 {
				fmt.Printf("  ---  ")
			} else {
				fmt.Printf("       ")
			}
			fmt.Printf("[ %3d ]\n", decoded[i])
		}
	} else {
		l := slots / 2
		A := make([][]uint64, l)
		B := make([][]uint64, l)
		for i := 0; i < l; i++ {
			A[i] = make([]uint64, l)
			B[i] = make([]uint64, l)
		}

		for k := range mat[0] {
			for i := 0; i < l; i++ {
				A[i][(i+k)%l] = mat[0][k][i]
			}
			for i := l; i < slots; i++ {
				B[i-l][(i+k)%l] = mat[0][k][i]
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
			fmt.Printf("[ %3d ]", data[i])

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
			fmt.Printf("[ %3d ]", data[i+l])

			if i == l/2-1 || i == l/2 {
				fmt.Printf("  ---  ")
			} else {
				fmt.Printf("       ")
			}
			fmt.Printf("[ %3d ]\n", decoded[i+l])
		}
	}
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
	evaluator := ckks_fv.NewMFVEvaluator(params, ckks_fv.EvaluationKey{Rlk: rlk, Rtks: rotkeys})

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

}

func main() {
	var input string
	var index int
	var err error

	choice := "Choose one of 0, 1, 2, 3, 4, 5, 6.\n"
	for true {
		fmt.Println("Choose an example:")
		fmt.Println("  (1): Transciphering")
		fmt.Println("  (2): Transciphering with Bootstrapping")
		fmt.Println("  (3): RtF Framework")
		fmt.Println("  (4): FV Linear Transform")
		fmt.Println("  (5): Multi Level FV")
		fmt.Println("  (6): FV Noise Estimate")
		fmt.Println("To exit, enter 0.")
		fmt.Print("Input: ")

		fmt.Scanln(&input)
		if index, err = strconv.Atoi(input); err == nil {
			switch index {
			case 0:
				return
			case 1:
				fmt.Println()
				transciphering()
			case 2:
				fmt.Println()
				transcipheringWithBoot()
			case 3:
				fmt.Println()
				RtF()
			case 4:
				fmt.Println()
				// fvLT()
				mfvLT()
			case 5:
				fmt.Println()
				MultiLevelFV()
			case 6:
				fmt.Println()
				fvNoiseBudget()
			default:
				fmt.Println(choice)
			}
		} else {
			fmt.Println(choice)
		}
	}
}
