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

func main() {
	var input string
	var index int
	var err error

	choice := "Choose one of 0, 1, 2.\n"
	for true {
		fmt.Println("Choose an example:")
		fmt.Println("  (1): Transciphering")
		fmt.Println("  (2): Transciphering with Bootstrapping")
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
			default:
				fmt.Println(choice)
			}
		} else {
			fmt.Println(choice)
		}
	}
}
