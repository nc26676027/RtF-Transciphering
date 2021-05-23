package ckks_fv

import (
	"math"
	//"fmt"
)

// HalfBootParameters is a struct for the default half-boot parameters
type HalfBootParameters struct {
	ResidualModuli
	KeySwitchModuli
	SineEvalModuli
	DiffScaleModulus
	CoeffsToSlotsModuli
	LogN         int
	LogSlots     int
	t            uint64
	Scale        float64
	Sigma        float64
	H            int     // Hamming weight of the secret key
	SinType      SinType // Chose betwenn [Sin(2*pi*x)] or [cos(2*pi*x/r) with double angle formula]
	MessageRatio float64 // Ratio between Q0 and m, i.e. Q[0]/|m|
	SinRange     int     // K parameter (interpolation in the range -K to K)
	SinDeg       int     // Degree of the interpolation
	SinRescal    int     // Number of rescale and double angle formula (only applies for cos)
	ArcSineDeg   int     // Degree of the Taylor arcsine composed with f(2*pi*x) (if zero then not used)
	MaxN1N2Ratio float64 // n1/n2 ratio for the bsgs algo for matrix x vector eval
}

// Params generates a new set of Parameters from the HalfBootParameters
func (hb *HalfBootParameters) Params() (p *Parameters, err error) {
	Qi := append(hb.ResidualModuli, hb.DiffScaleModulus...)
	Qi = append(Qi, hb.SineEvalModuli.Qi...)
	Qi = append(Qi, hb.CoeffsToSlotsModuli.Qi...)

	if p, err = NewParametersFromModuli(hb.LogN, &Moduli{Qi, hb.KeySwitchModuli}, hb.t); err != nil {
		return nil, err
	}

	p.SetScale(hb.Scale)
	p.SetLogSlots(hb.LogSlots)
	p.SetSigma(hb.Sigma)
	return
}

// Copy return a new HalfBootParameters which is a copy of the target
func (hb *HalfBootParameters) Copy() *HalfBootParameters {
	paramsCopy := &HalfBootParameters{
		LogN:         hb.LogN,
		LogSlots:     hb.LogSlots,
		t:            hb.t,
		Scale:        hb.Scale,
		Sigma:        hb.Sigma,
		H:            hb.H,
		SinType:      hb.SinType,
		MessageRatio: hb.MessageRatio,
		SinRange:     hb.SinRange,
		SinDeg:       hb.SinDeg,
		SinRescal:    hb.SinRescal,
		ArcSineDeg:   hb.ArcSineDeg,
		MaxN1N2Ratio: hb.MaxN1N2Ratio,
	}

	// KeySwitchModuli
	paramsCopy.KeySwitchModuli = make([]uint64, len(hb.KeySwitchModuli))
	copy(paramsCopy.KeySwitchModuli, hb.KeySwitchModuli)

	// ResidualModuli
	paramsCopy.ResidualModuli = make([]uint64, len(hb.ResidualModuli))
	copy(paramsCopy.ResidualModuli, hb.ResidualModuli)

	// CoeffsToSlotsModuli
	paramsCopy.CoeffsToSlotsModuli.Qi = make([]uint64, hb.CtSDepth(true))
	copy(paramsCopy.CoeffsToSlotsModuli.Qi, hb.CoeffsToSlotsModuli.Qi)

	paramsCopy.CoeffsToSlotsModuli.ScalingFactor = make([][]float64, hb.CtSDepth(true))
	for i := range paramsCopy.CoeffsToSlotsModuli.ScalingFactor {
		paramsCopy.CoeffsToSlotsModuli.ScalingFactor[i] = make([]float64, len(hb.CoeffsToSlotsModuli.ScalingFactor[i]))
		copy(paramsCopy.CoeffsToSlotsModuli.ScalingFactor[i], hb.CoeffsToSlotsModuli.ScalingFactor[i])
	}

	// SineEvalModuli
	paramsCopy.SineEvalModuli.Qi = make([]uint64, len(hb.SineEvalModuli.Qi))
	copy(paramsCopy.SineEvalModuli.Qi, hb.SineEvalModuli.Qi)
	paramsCopy.SineEvalModuli.ScalingFactor = hb.SineEvalModuli.ScalingFactor

	// DiffScaelModulus
	paramsCopy.DiffScaleModulus = make([]uint64, 1)
	copy(paramsCopy.DiffScaleModulus, hb.DiffScaleModulus)

	return paramsCopy
}

// DiffScaleModulus is used to set scale after the SineEval step.
type DiffScaleModulus []uint64

// MaxLevel returns the maximum level of the halfboot parameters
func (hb *HalfBootParameters) MaxLevel() int {
	return len(hb.ResidualModuli) + len(hb.DiffScaleModulus) + len(hb.CoeffsToSlotsModuli.Qi) + len(hb.SineEvalModuli.Qi) - 1
}

// SineEvalDepth returns the depth of the SineEval. If true, then also
// counts the double angle formula.
func (hb *HalfBootParameters) SineEvalDepth(withRescale bool) int {
	depth := int(math.Ceil(math.Log2(float64(hb.SinDeg + 1))))

	if withRescale {
		depth += hb.SinRescal
	}

	return depth
}

// ArcSineDepth returns the depth of the arcsine polynomial.
func (hb *HalfBootParameters) ArcSineDepth() int {
	return int(math.Ceil(math.Log2(float64(hb.ArcSineDeg + 1))))
}

// CtSDepth returns the number of levels allocated to CoeffsToSlots.
// If actual == true then returns the number of moduli consumed, else
// returns the factorization depth.
func (hb *HalfBootParameters) CtSDepth(actual bool) (depth int) {
	if actual {
		depth = len(hb.CoeffsToSlotsModuli.ScalingFactor)
	} else {
		for i := range hb.CoeffsToSlotsModuli.ScalingFactor {
			for range hb.CoeffsToSlotsModuli.ScalingFactor[i] {
				depth++
			}
		}
	}

	return
}

// CtSLevels returns the index of the Qi used int CoeffsToSlots
func (hb *HalfBootParameters) CtSLevels() (ctsLevel []int) {
	ctsLevel = []int{}
	for i := range hb.CoeffsToSlotsModuli.Qi {
		for range hb.CoeffsToSlotsModuli.ScalingFactor[hb.CtSDepth(true)-1-i] {
			ctsLevel = append(ctsLevel, hb.MaxLevel()-i)
		}
	}

	return
}

// GenCoeffsToSlotsMatrixWithoutRepack generates the factorized encoding matrix
// scaling : constant by witch the all the matrices will be multiplied by
// encoder : ckks.Encoder
func (hb *HalfBootParameters) GenCoeffsToSlotsMatrixWithoutRepack(scaling complex128, encoder Encoder) []*PtDiagMatrix {

	logSlots := hb.LogSlots
	slots := 1 << logSlots
	depth := hb.CtSDepth(false)
	logdSlots := logSlots + 1
	if logdSlots == hb.LogN {
		logdSlots--
	}

	roots := computeRoots(slots << 1)
	pow5 := make([]int, (slots<<1)+1)
	pow5[0] = 1
	for i := 1; i < (slots<<1)+1; i++ {
		pow5[i] = pow5[i-1] * 5
		pow5[i] &= (slots << 2) - 1
	}

	ctsLevels := hb.CtSLevels()

	// CoeffsToSlots vectors
	pDFTInv := make([]*PtDiagMatrix, len(ctsLevels))
	pVecDFTInv := computeDFTMatricesWithoutRepack(logSlots, logdSlots, depth, roots, pow5, scaling, true)
	cnt := 0
	for i := range hb.CoeffsToSlotsModuli.ScalingFactor {
		for j := range hb.CoeffsToSlotsModuli.ScalingFactor[hb.CtSDepth(true)-i-1] {
			pDFTInv[cnt] = encoder.EncodeDiagMatrixAtLvl(ctsLevels[cnt], pVecDFTInv[cnt], hb.CoeffsToSlotsModuli.ScalingFactor[hb.CtSDepth(true)-i-1][j], hb.MaxN1N2Ratio, logdSlots)
			cnt++
		}
	}

	return pDFTInv
}

func computeDFTMatricesWithoutRepack(logSlots, logdSlots, maxDepth int, roots []complex128, pow5 []int, diffscale complex128, inverse bool) (plainVector []map[int][]complex128) {

	bitreversed := false

	var fftLevel, depth, nextfftLevel int

	fftLevel = logSlots

	var a, b, c [][]complex128

	if inverse {
		a, b, c = fftInvPlainVec(logSlots, 1<<logdSlots, roots, pow5)
	} else {
		a, b, c = fftPlainVec(logSlots, 1<<logdSlots, roots, pow5)
	}

	plainVector = make([]map[int][]complex128, maxDepth)

	// We compute the chain of merge in order or reverse order depending if its DFT or InvDFT because
	// the way the levels are collapsed has an inpact on the total number of rotations and keys to be
	// stored. Ex. instead of using 255 + 64 plaintext vectors, we can use 127 + 128 plaintext vectors
	// by reversing the order of the merging.
	merge := make([]int, maxDepth)
	for i := 0; i < maxDepth; i++ {

		depth = int(math.Ceil(float64(fftLevel) / float64(maxDepth-i)))

		if inverse {
			merge[i] = depth
		} else {
			merge[len(merge)-i-1] = depth

		}

		fftLevel -= depth
	}

	fftLevel = logSlots
	for i := 0; i < maxDepth; i++ {
		// First layer of the i-th level of the DFT
		plainVector[i] = genFFTDiagMatrix(logSlots, fftLevel, a[logSlots-fftLevel], b[logSlots-fftLevel], c[logSlots-fftLevel], inverse, bitreversed)

		// Merges the layer with the next levels of the DFT if the total depth requires it.
		nextfftLevel = fftLevel - 1
		for j := 0; j < merge[i]-1; j++ {
			plainVector[i] = multiplyFFTMatrixWithNextFFTLevel(plainVector[i], logSlots, 1<<logSlots, nextfftLevel, a[logSlots-nextfftLevel], b[logSlots-nextfftLevel], c[logSlots-nextfftLevel], inverse, bitreversed)
			nextfftLevel--
		}

		fftLevel -= merge[i]
	}

	// Rescaling of the DFT matrix of the SlotsToCoeffs/CoeffsToSlots
	for j := range plainVector {
		for x := range plainVector[j] {
			for i := range plainVector[j][x] {
				plainVector[j][x][i] *= diffscale
			}
		}
	}

	return
}

func (hb *HalfBootParameters) SetLogSlots(logslot int) {
	hb.LogSlots = logslot
}

// DefaultHalfBootParams are default halfboot params for the half-bootstrapping.
var DefaultHalfBootParams = []*HalfBootParameters{

	// SET I
	// 1546
	{
		LogN:     16,
		LogSlots: 15,
		Scale:    1 << 40,
		t:        0x7fea0001, // temporal value for t
		Sigma:    DefaultSigma,
		ResidualModuli: []uint64{
			0x10000000006e0001, // 60 Q0
			0x10000140001,      // 40
			0xffffe80001,       // 40
			0xffffc40001,       // 40
			0x100003e0001,      // 40
			0xffffb20001,       // 40
			0x10000500001,      // 40
			0xffff940001,       // 40
			0xffff8a0001,       // 40
			0xffff820001,       // 40
		},
		KeySwitchModuli: []uint64{
			0x1fffffffffe00001, // Pi 61
			0x1fffffffffc80001, // Pi 61
			0x1fffffffffb40001, // Pi 61
			0x1fffffffff500001, // Pi 61
			0x1fffffffff420001, // Pi 61
		},
		DiffScaleModulus: []uint64{
			0x7fffe60001, // 39
		},
		// SlotsToCoeffsModuli: SlotsToCoeffsModuli{
		// 	Qi: []uint64{
		// 		0x7fffe60001, // 39 StC
		// 		0x7fffe40001, // 39 StC
		// 		0x7fffe00001, // 39 StC
		// 	},
		// 	ScalingFactor: [][]float64{
		// 		{0x7fffe60001},
		// 		{0x7fffe40001},
		// 		{0x7fffe00001},
		// 	},
		// },
		SineEvalModuli: SineEvalModuli{
			Qi: []uint64{
				0xfffffffff840001,  // 60 Sine (double angle)
				0x1000000000860001, // 60 Sine (double angle)
				0xfffffffff6a0001,  // 60 Sine
				0x1000000000980001, // 60 Sine
				0xfffffffff5a0001,  // 60 Sine
				0x1000000000b00001, // 60 Sine
				0x1000000000ce0001, // 60 Sine
				0xfffffffff2a0001,  // 60 Sine
			},
			ScalingFactor: 1 << 60,
		},
		CoeffsToSlotsModuli: CoeffsToSlotsModuli{
			Qi: []uint64{
				0x100000000060001, // 58 CtS
				0xfffffffff00001,  // 58 CtS
				0xffffffffd80001,  // 58 CtS
				0x1000000002a0001, // 58 CtS
			},
			ScalingFactor: [][]float64{
				{0x100000000060001},
				{0xfffffffff00001},
				{0xffffffffd80001},
				{0x1000000002a0001},
			},
		},
		H:            192,
		SinType:      Cos1,
		MessageRatio: 256.0,
		SinRange:     25,
		SinDeg:       63,
		SinRescal:    2,
		ArcSineDeg:   0,
		MaxN1N2Ratio: 16.0,
	},

	// SET II
	// 1547
	{
		LogN:     16,
		LogSlots: 15,
		t:        0x7fea0001, // temporal value for t
		Scale:    1 << 45,
		Sigma:    DefaultSigma,
		ResidualModuli: []uint64{
			0x10000000006e0001, // 60 Q0
			0x2000000a0001,     // 45
			0x2000000e0001,     // 45
			0x1fffffc20001,     // 45
			0x200000440001,     // 45
			0x200000500001,     // 45
		},
		KeySwitchModuli: []uint64{
			0x1fffffffffe00001, // Pi 61
			0x1fffffffffc80001, // Pi 61
			0x1fffffffffb40001, // Pi 61
			0x1fffffffff500001, // Pi 61
		},
		DiffScaleModulus: []uint64{
			0x3ffffe80001, // 42
		},
		// SlotsToCoeffsModuli: SlotsToCoeffsModuli{
		// 	Qi: []uint64{
		// 		0x3ffffe80001, //42 StC
		// 		0x3ffffd20001, //42 StC
		// 		0x3ffffca0001, //42 StC
		// 	},
		// 	ScalingFactor: [][]float64{
		// 		{0x3ffffe80001},
		// 		{0x3ffffd20001},
		// 		{0x3ffffca0001},
		// 	},
		// },
		SineEvalModuli: SineEvalModuli{
			Qi: []uint64{
				0xffffffffffc0001,  // ArcSine
				0xfffffffff240001,  // ArcSine
				0x1000000000f00001, // ArcSine
				0xfffffffff840001,  // Double angle
				0x1000000000860001, // Double angle
				0xfffffffff6a0001,  // Sine
				0x1000000000980001, // Sine
				0xfffffffff5a0001,  // Sine
				0x1000000000b00001, // Sine
				0x1000000000ce0001, // Sine
				0xfffffffff2a0001,  // Sine
			},
			ScalingFactor: 1 << 60,
		},
		CoeffsToSlotsModuli: CoeffsToSlotsModuli{
			Qi: []uint64{
				0x400000000360001, // 58 CtS
				0x3ffffffffbe0001, // 58 CtS
				0x400000000660001, // 58 CtS
				0x4000000008a0001, // 58 CtS
			},
			ScalingFactor: [][]float64{
				{0x400000000360001},
				{0x3ffffffffbe0001},
				{0x400000000660001},
				{0x4000000008a0001},
			},
		},
		H:            192,
		SinType:      Cos1,
		MessageRatio: 4.0,
		SinRange:     25,
		SinDeg:       63,
		SinRescal:    2,
		ArcSineDeg:   7,
		MaxN1N2Ratio: 16.0,
	},

	// SET III
	// 1553
	{
		LogN:     16,
		LogSlots: 15,
		t:        0x7fea0001, // temporal value for t
		Scale:    1 << 30,
		Sigma:    DefaultSigma,
		ResidualModuli: []uint64{
			0x80000000080001,   // 55 Q0
			0xffffffffffc0001,  // 60
			0x10000000006e0001, // 60
			0xfffffffff840001,  // 60
			0x1000000000860001, // 60
			0xfffffffff6a0001,  // 60
			0x1000000000980001, // 60
			0xfffffffff5a0001,  // 60
		},
		KeySwitchModuli: []uint64{
			0x1fffffffffe00001, // Pi 61
			0x1fffffffffc80001, // Pi 61
			0x1fffffffffb40001, // Pi 61
			0x1fffffffff500001, // Pi 61
			0x1fffffffff420001, // Pi 61
		},
		DiffScaleModulus: []uint64{
			0x40020001, // 30
		},
		// SlotsToCoeffsModuli: SlotsToCoeffsModuli{
		// 	Qi: []uint64{
		// 		0x1000000000b00001, // 60 StC  (30)
		// 		0x1000000000ce0001, // 60 StC  (30+30)
		// 	},
		// 	ScalingFactor: [][]float64{
		// 		{1073741824.0},
		// 		{1073741824.0062866, 1073741824.0062866},
		// 	},
		// },
		SineEvalModuli: SineEvalModuli{
			Qi: []uint64{
				0x80000000440001, // 55 Sine (double angle)
				0x7fffffffba0001, // 55 Sine (double angle)
				0x80000000500001, // 55 Sine
				0x7fffffffaa0001, // 55 Sine
				0x800000005e0001, // 55 Sine
				0x7fffffff7e0001, // 55 Sine
				0x7fffffff380001, // 55 Sine
				0x80000000ca0001, // 55 Sine
			},
			ScalingFactor: 1 << 55,
		},
		CoeffsToSlotsModuli: CoeffsToSlotsModuli{
			Qi: []uint64{
				0x200000000e0001, // 53 CtS
				0x20000000140001, // 53 CtS
				0x20000000280001, // 53 CtS
				0x1fffffffd80001, // 53 CtS
			},
			ScalingFactor: [][]float64{
				{0x200000000e0001},
				{0x20000000140001},
				{0x20000000280001},
				{0x1fffffffd80001},
			},
		},
		H:            192,
		SinType:      Cos1,
		MessageRatio: 256.0,
		SinRange:     25,
		SinDeg:       63,
		SinRescal:    2,
		ArcSineDeg:   0,
		MaxN1N2Ratio: 16.0,
	},

	// Set IV
	// 1792
	{
		LogN:     16,
		LogSlots: 15,
		t:        0x7fea0001, // temporal value for t
		Scale:    1 << 40,
		Sigma:    DefaultSigma,
		ResidualModuli: []uint64{
			0x4000000120001, // 60 Q0
			0x10000140001,
			0xffffe80001,
			0xffffc40001,
			0x100003e0001,
			0xffffb20001,
			0x10000500001,
			0xffff940001,
			0xffff8a0001,
			0xffff820001,
		},
		KeySwitchModuli: []uint64{
			0x1fffffffffe00001, // Pi 61
			0x1fffffffffc80001, // Pi 61
			0x1fffffffffb40001, // Pi 61
			0x1fffffffff500001, // Pi 61
			0x1fffffffff420001, // Pi 61
			0x1fffffffff380001, // Pi 61
		},
		DiffScaleModulus: []uint64{
			0xffa0001, // 28
		},
		// SlotsToCoeffsModuli: SlotsToCoeffsModuli{
		// 	Qi: []uint64{
		// 		0x100000000060001, // 56 StC (28 + 28)
		// 		0xffa0001,         // 28 StC
		// 	},
		// 	ScalingFactor: [][]float64{
		// 		{268435456.0007324, 268435456.0007324},
		// 		{0xffa0001},
		// 	},
		// },
		SineEvalModuli: SineEvalModuli{
			Qi: []uint64{
				0xffffffffffc0001,  // 60 Sine (double angle)
				0x10000000006e0001, // 60 Sine (double angle)
				0xfffffffff840001,  // 60 Sine (double angle)
				0x1000000000860001, // 60 Sine (double angle)
				0xfffffffff6a0001,  // 60 Sine
				0x1000000000980001, // 60 Sine
				0xfffffffff5a0001,  // 60 Sine
				0x1000000000b00001, // 60 Sine
				0x1000000000ce0001, // 60 Sine
				0xfffffffff2a0001,  // 60 Sine
				0xfffffffff240001,  // 60 Sine
				0x1000000000f00001, // 60 Sine
			},
			ScalingFactor: 1 << 60,
		},
		CoeffsToSlotsModuli: CoeffsToSlotsModuli{
			Qi: []uint64{
				0x200000000e0001, // 53 CtS
				0x20000000140001, // 53 CtS
				0x20000000280001, // 53 CtS
				0x1fffffffd80001, // 53 CtS
			},
			ScalingFactor: [][]float64{
				{0x200000000e0001},
				{0x20000000140001},
				{0x20000000280001},
				{0x1fffffffd80001},
			},
		},
		H:            32768,
		SinType:      Cos2,
		MessageRatio: 256.0,
		SinRange:     325,
		SinDeg:       255,
		SinRescal:    4,
		ArcSineDeg:   0,
		MaxN1N2Ratio: 16.0,
	},

	// Set V
	// 768
	{
		LogN:     15,
		LogSlots: 14,
		t:        0x7fea0001, // temporal value for t
		Scale:    1 << 25,
		Sigma:    DefaultSigma,
		ResidualModuli: []uint64{
			0x1fff90001,     // 32 Q0
			0x4000000420001, // 50
			0x1fc0001,       // 25
		},
		KeySwitchModuli: []uint64{
			0x7fffffffe0001, // 51
			0x8000000110001, // 51
		},
		DiffScaleModulus: []uint64{
			0x40020001, // 30
		},
		// SlotsToCoeffsModuli: SlotsToCoeffsModuli{
		// 	Qi: []uint64{
		// 		0xffffffffffc0001, // 60 StC (30+30)
		// 	},
		// 	ScalingFactor: [][]float64{
		// 		{1073741823.9998779, 1073741823.9998779},
		// 	},
		// },
		SineEvalModuli: SineEvalModuli{
			Qi: []uint64{
				0x4000000120001, // 50 Sine
				0x40000001b0001, // 50 Sine
				0x3ffffffdf0001, // 50 Sine
				0x4000000270001, // 50 Sine
				0x3ffffffd20001, // 50 Sine
				0x3ffffffcd0001, // 50 Sine
				0x4000000350001, // 50 Sine
				0x3ffffffc70001, // 50 Sine
			},
			ScalingFactor: 1 << 50,
		},
		CoeffsToSlotsModuli: CoeffsToSlotsModuli{
			Qi: []uint64{
				0x1fffffff50001, // 49 CtS
				0x1ffffffea0001, // 49 CtS
			},
			ScalingFactor: [][]float64{
				{0x1fffffff50001},
				{0x1ffffffea0001},
			},
		},
		H:            192,
		SinType:      Cos1,
		MessageRatio: 256.0,
		SinRange:     25,
		SinDeg:       63,
		SinRescal:    2,
		ArcSineDeg:   0,
		MaxN1N2Ratio: 16.0,
	},
}
