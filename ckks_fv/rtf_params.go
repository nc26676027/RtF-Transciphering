package ckks_fv

/* ModDown Parameters*/
// ModDownParams denotes optimized modulus switching indices for given RtF parameters
// (See github.com/smilecjf/lattigo/v2/examples/ckks_fv/main for an example)
// StcModDownParams assumes that the decoding matrix is factorized with radix 2.

// HERA mod down indices for 80-bit security parameter
var HeraModDownParams80 = [][]int{
	{6, 2, 2, 2, 3},  // with RtF param 128f
	{10, 2, 3, 3, 3}, // with RtF param 128s
	{7, 2, 2, 2, 2},  // with RtF param 128af
	{11, 2, 2, 3, 2}, // with RtF param 128as
}

// HERA mod down indices for 128-bit security parameter
var HeraModDownParams128 = [][]int{
	{4, 2, 2, 2, 2, 3}, // with RtF param 128f
	{9, 2, 3, 3, 3, 2}, // with RtF param 128s
	{5, 2, 2, 2, 2, 2}, // with RtF param 128af
	{9, 2, 2, 2, 3, 2}, // with RtF param 128as
}

// SlotToCoeff mod down indices for 80-bit security
var StcModDownParams80 = [][]int{
	{1, 0, 1, 1, 1, 1, 1, 1}, // with RtF param 128f and radix 2
	{0},                      // with RtF param 128s and radix 0
	{1, 1, 0, 1, 1, 1, 0, 0}, // with RtF param 128af and radix 2
	{0},                      // with RtF param 128as and radix 0
}

var StcModDownParams128 = [][]int{
	{0, 1, 1, 1, 1, 1, 1, 1}, // with RtF param 128f and radix 2
	{1},                      // with RtF param 128s and radix 0
	{1, 1, 0, 1, 1, 1, 0, 0}, // with RtF param 128af and radix 2
	{0, 1},                   // with RtF param 128as and radix 2
}

var RtFParams = []*HalfBootParameters{
	// 128f
	// Use full coefficients for data encoding
	{
		LogN:     16,
		LogSlots: 15,
		Scale:    1 << 40,
		t:        268042241, // 28-bit
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
			0xffff780001,       // 40
			0x10000960001,      // 40
		},
		KeySwitchModuli: []uint64{
			0x1fffffffffe00001, // Pi 61
			0x1fffffffffc80001, // Pi 61
			0x1fffffffffb40001, // Pi 61
			0x1fffffffff500001, // Pi 61
			0x1fffffffff420001, // Pi 61
		},
		DiffScaleModulus: []uint64{
			0xfc0001, // 24
		},
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
				0x100000000060001, // 56 CtS
				0xfffffffff00001,  // 56 CtS
				0xffffffffd80001,  // 56 CtS
				0x1000000002a0001, // 56 CtS
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
		MessageRatio: 512.0,
		SinRange:     25,
		SinDeg:       63,
		SinRescal:    2,
		ArcSineDeg:   0,
		MaxN1N2Ratio: 16.0,
	},

	// 128s
	// Use only 4 slots for data encoding
	{
		LogN:     16,
		LogSlots: 4,
		Scale:    1 << 40,
		t:        268042241, // 28-bit
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
			0xffff780001,       // 40
			0x10000960001,      // 40
		},
		KeySwitchModuli: []uint64{
			0x1fffffffffe00001, // Pi 61
			0x1fffffffffc80001, // Pi 61
			0x1fffffffffb40001, // Pi 61
			0x1fffffffff500001, // Pi 61
			0x1fffffffff420001, // Pi 61
		},
		DiffScaleModulus: []uint64{
			0xfc0001, // 24
		},
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
				0x100000000060001, // 56 CtS
				0xfffffffff00001,  // 56 CtS
				0xffffffffd80001,  // 56 CtS
				0x1000000002a0001, // 56 CtS
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
		MessageRatio: 512.0,
		SinRange:     25,
		SinDeg:       63,
		SinRescal:    2,
		ArcSineDeg:   0,
		MaxN1N2Ratio: 16.0,
	},

	// 128af
	// Use full coefficients for data encoding
	// with arcsine evaluation
	{
		LogN:     16,
		LogSlots: 15,
		t:        33292289, // 25-bit
		Scale:    1 << 45,
		Sigma:    DefaultSigma,
		ResidualModuli: []uint64{
			0x10000000006e0001, // 60 Q0
			0x2000000a0001,     // 45
			0x2000000e0001,     // 45
			0x1fffffc20001,     // 45
			0x200000440001,     // 45
			0x200000500001,     // 45
			0x200000620001,     // 45
			0x1fffff980001,     // 45
		},
		KeySwitchModuli: []uint64{
			0x1fffffffffe00001, // Pi 61
			0x1fffffffffc80001, // Pi 61
			0x1fffffffffb40001, // Pi 61
			0x1fffffffff500001, // Pi 61
		},
		DiffScaleModulus: []uint64{
			0x2a0001, // 22
		},
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
		MessageRatio: 16.0,
		SinRange:     25,
		SinDeg:       63,
		SinRescal:    2,
		ArcSineDeg:   7,
		MaxN1N2Ratio: 16.0,
	},

	// 128as
	// Use only 4 slots for data encoding
	// with arcsine evaluation
	{
		LogN:     16,
		LogSlots: 4,
		t:        33292289, // 25-bit
		Scale:    1 << 45,
		Sigma:    DefaultSigma,
		ResidualModuli: []uint64{
			0x10000000006e0001, // 60 Q0
			0x2000000a0001,     // 45
			0x2000000e0001,     // 45
			0x1fffffc20001,     // 45
			0x200000440001,     // 45
			0x200000500001,     // 45
			0x200000620001,     // 45
			0x1fffff980001,     // 45
		},
		KeySwitchModuli: []uint64{
			0x1fffffffffe00001, // Pi 61
			0x1fffffffffc80001, // Pi 61
			0x1fffffffffb40001, // Pi 61
			0x1fffffffff500001, // Pi 61
		},
		DiffScaleModulus: []uint64{
			0x2a0001, // 22
		},
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
		MessageRatio: 16.0,
		SinRange:     25,
		SinDeg:       63,
		SinRescal:    2,
		ArcSineDeg:   7,
		MaxN1N2Ratio: 16.0,
	},
}
