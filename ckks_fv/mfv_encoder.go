// Package bfv implements a RNS-accelerated Fan-Vercauteren version of Brakerski's scale invariant homomorphic encryption scheme. It provides modular arithmetic over the integers.
package ckks_fv

import (
	"fmt"
	"unsafe"

	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
)

// GaloisGen is an integer of order N=2^d modulo M=2N and that spans Z_M with the integer -1.
// The j-th ring automorphism takes the root zeta to zeta^(5j).
// const GaloisGen int = 5

// Encoder is an interface for plaintext encoding and decoding operations. It provides methods to embed []uint64 and []int64 types into
// the various plaintext types and the inverse operations. It also provides methodes to convert between the different plaintext types.
// The different plaintext types represent different embeddings of the message in the polynomial space. This relation is illustrated in
// The figure below:
//
// []uint64 --- Encoder.EncodeUintRingT(.) -┬-> PlaintextRingT -┬-> Encoder.ScaleUp(.) -----> Plaintext
// []uint64 --- Encoder.EncodeIntRingT(.) --┘                   └-> Encoder.RingTToMul(.) ---> PlaintextMul
//
//
// The different plaintext types have different efficiency-related caracteristics that we summarize in the Table below. For more information
// about the different plaintext types, see plaintext.go.
//
// Relative efficiency of operation
//  -----------------------------------------------------------------------
// |                      |  PlaintextRingT  |  Plaintext  | PlaintextMul  |
//  -----------------------------------------------------------------------
// | Encoding/Decoding    |    Faster      |    Slower   |    Slower       |
// | Memory size          |    Smaller     |    Larger   |    Larger       |
// | Ct-Pt Add / Sub      |    Slower      |    Faster   |    N/A          |
// | Ct-Pt Mul            |    Faster      |    Slower   |    Much Faster  |
//  -----------------------------------------------------------------------
//
type MFVEncoder interface {
	EncodeUint(coeffs []uint64, pt *Plaintext)
	EncodeUintRingT(coeffs []uint64, pt *PlaintextRingT)
	EncodeUintMul(coeffs []uint64, pt *PlaintextMul)
	EncodeInt(coeffs []int64, pt *Plaintext)
	EncodeIntRingT(coeffs []int64, pt *PlaintextRingT)
	EncodeIntMul(coeffs []int64, pt *PlaintextMul)

	ScaleUp(*PlaintextRingT, *Plaintext)
	ScaleDown(pt *Plaintext, ptRt *PlaintextRingT)
	RingTToMul(ptRt *PlaintextRingT, ptmul *PlaintextMul)
	MulToRingT(pt *PlaintextMul, ptRt *PlaintextRingT)

	DecodeRingT(pt interface{}, ptRt *PlaintextRingT)
	DecodeUint(pt interface{}, coeffs []uint64)
	DecodeInt(pt interface{}, coeffs []int64)
	DecodeUintNew(pt interface{}) (coeffs []uint64)
	DecodeIntNew(pt interface{}) (coeffs []int64)

	EncodeDiagMatrixT(level int, vector map[int][]uint64, maxM1N2Ratio float64, logSlots int) (matrix *PtDiagMatrixT)
	GenSlotToCoeffMatFV() (pDcds [][]*PtDiagMatrixT)
}

type multiLevelContext struct {
	maxLevel   int
	ringQs     []*ring.Ring
	scalers    []ring.Scaler
	deltasMont [][]uint64
}

// Encoder is a structure that stores the parameters to encode values on a plaintext in a SIMD (Single-Instruction Multiple-Data) fashion.
type mfvEncoder struct {
	params *Parameters

	ringP *ring.Ring
	ringT *ring.Ring

	indexMatrix []uint64
	deltaPMont  []uint64
	multiLevelContext

	tmpPoly *ring.Poly
	tmpPtRt *PlaintextRingT
}

func newMultiLevelContext(params *Parameters) multiLevelContext {
	var err error
	modCount := len(params.qi)
	ringQs := make([]*ring.Ring, modCount)
	scalers := make([]ring.Scaler, modCount)
	deltasMont := make([][]uint64, modCount)

	for i := 0; i < modCount; i++ {
		var ringQi *ring.Ring
		if ringQi, err = ring.NewRing(params.N(), params.qi[:i+1]); err != nil {
			panic(err)
		}
		ringQs[i] = ringQi
		deltasMont[i] = GenLiftParams(ringQi, params.t)
		scalers[i] = ring.NewRNSScaler(params.t, ringQi)
	}

	return multiLevelContext{
		maxLevel:   modCount - 1,
		ringQs:     ringQs,
		scalers:    scalers,
		deltasMont: deltasMont,
	}
}

// NewMFVEncoder creates a new encoder from the provided parameters.
func NewMFVEncoder(params *Parameters) MFVEncoder {

	var ringP, ringT *ring.Ring
	var err error

	context := newMultiLevelContext(params)

	if ringP, err = ring.NewRing(params.N(), params.pi); err != nil {
		panic(err)
	}

	if ringT, err = ring.NewRing(params.N(), []uint64{params.t}); err != nil {
		panic(err)
	}

	var m, pos, index1, index2 int

	slots := params.N()

	indexMatrix := make([]uint64, slots)

	logN := params.LogN()

	rowSize := params.N() >> 1
	m = (params.N() << 1)
	pos = 1

	for i := 0; i < rowSize; i++ {

		index1 = (pos - 1) >> 1
		index2 = (m - pos - 1) >> 1

		indexMatrix[i] = utils.BitReverse64(uint64(index1), uint64(logN))
		indexMatrix[i|rowSize] = utils.BitReverse64(uint64(index2), uint64(logN))

		pos *= GaloisGen
		pos &= (m - 1)
	}

	return &mfvEncoder{
		params:            params.Copy(),
		ringP:             ringP,
		ringT:             ringT,
		indexMatrix:       indexMatrix,
		deltaPMont:        GenLiftParams(ringP, params.t),
		multiLevelContext: context,
		tmpPoly:           ringT.NewPoly(),
		tmpPtRt:           NewPlaintextRingT(params),
	}
}

// EncodeUintRingT encodes a slice of uint64 into a Plaintext in R_t
func (encoder *mfvEncoder) EncodeUintRingT(coeffs []uint64, p *PlaintextRingT) {
	if len(coeffs) > len(encoder.indexMatrix) {
		panic("invalid input to encode: number of coefficients must be smaller or equal to the ring degree")
	}

	if len(p.value.Coeffs[0]) != len(encoder.indexMatrix) {
		panic("invalid plaintext to receive encoding: number of coefficients does not match the ring degree")
	}

	for i := 0; i < len(coeffs); i++ {
		p.value.Coeffs[0][encoder.indexMatrix[i]] = coeffs[i]
	}

	for i := len(coeffs); i < len(encoder.indexMatrix); i++ {
		// p.value.Coeffs[0][encoder.indexMatrix[i]] = 0
		p.value.Coeffs[0][encoder.indexMatrix[i]] = coeffs[i%len(coeffs)]
	}

	encoder.ringT.InvNTT(p.value, p.value)
}

// EncodeUint encodes an uint64 slice of size at most N on a plaintext.
func (encoder *mfvEncoder) EncodeUint(coeffs []uint64, p *Plaintext) {
	ptRt := &PlaintextRingT{p.Element, p.Element.value[0]}

	// Encodes the values in RingT
	encoder.EncodeUintRingT(coeffs, ptRt)

	// Scales by Q/t
	encoder.ScaleUp(ptRt, p)
}

func (encoder *mfvEncoder) EncodeUintMul(coeffs []uint64, p *PlaintextMul) {

	ptRt := &PlaintextRingT{p.Element, p.Element.value[0]}

	// Encodes the values in RingT
	encoder.EncodeUintRingT(coeffs, ptRt)

	// Puts in NTT+Montgomery domains of ringQ
	encoder.RingTToMul(ptRt, p)
}

// EncodeInt encodes an int64 slice of size at most N on a plaintext. It also encodes the sign of the given integer (as its inverse modulo the plaintext modulus).
// The sign will correctly decode as long as the absolute value of the coefficient does not exceed half of the plaintext modulus.
func (encoder *mfvEncoder) EncodeIntRingT(coeffs []int64, p *PlaintextRingT) {

	if len(coeffs) > len(encoder.indexMatrix) {
		panic("invalid input to encode: number of coefficients must be smaller or equal to the ring degree")
	}

	if len(p.value.Coeffs[0]) != len(encoder.indexMatrix) {
		panic("invalid plaintext to receive encoding: number of coefficients does not match the ring degree")
	}

	for i := 0; i < len(coeffs); i++ {

		if coeffs[i] < 0 {
			p.value.Coeffs[0][encoder.indexMatrix[i]] = uint64(int64(encoder.params.t) + coeffs[i])
		} else {
			p.value.Coeffs[0][encoder.indexMatrix[i]] = uint64(coeffs[i])
		}
	}

	for i := len(coeffs); i < len(encoder.indexMatrix); i++ {
		p.value.Coeffs[0][encoder.indexMatrix[i]] = 0
	}

	encoder.ringT.InvNTTLazy(p.value, p.value)
}

func (encoder *mfvEncoder) EncodeInt(coeffs []int64, p *Plaintext) {
	ptRt := &PlaintextRingT{p.Element, p.value}

	// Encodes the values in RingT
	encoder.EncodeIntRingT(coeffs, ptRt)

	// Scales by Q/t
	encoder.ScaleUp(ptRt, p)
}

func (encoder *mfvEncoder) EncodeIntMul(coeffs []int64, p *PlaintextMul) {
	ptRt := &PlaintextRingT{p.Element, p.value}

	// Encodes the values in RingT
	encoder.EncodeIntRingT(coeffs, ptRt)

	// Puts in NTT+Montgomery domains of ringQ
	encoder.RingTToMul(ptRt, p)
}

// ScaleUp transforms a PlaintextRingT (R_t) into a Plaintext (R_q) by scaling up the coefficient by Q/t.
func (encoder *mfvEncoder) ScaleUp(ptRt *PlaintextRingT, pt *Plaintext) {
	level := pt.Level()
	ringQ := encoder.ringQs[level]
	deltaMont := encoder.deltasMont[level]
	scaleUp(ringQ, deltaMont, ptRt.value, pt.value)
}

func scaleUp(ringQ *ring.Ring, deltaMont []uint64, pIn, pOut *ring.Poly) {

	for i := len(ringQ.Modulus) - 1; i >= 0; i-- {
		out := pOut.Coeffs[i]
		in := pIn.Coeffs[0]
		d := deltaMont[i]
		qi := ringQ.Modulus[i]
		mredParams := ringQ.MredParams[i]

		for j := 0; j < ringQ.N; j = j + 8 {

			x := (*[8]uint64)(unsafe.Pointer(&in[j]))
			z := (*[8]uint64)(unsafe.Pointer(&out[j]))

			z[0] = ring.MRed(x[0], d, qi, mredParams)
			z[1] = ring.MRed(x[1], d, qi, mredParams)
			z[2] = ring.MRed(x[2], d, qi, mredParams)
			z[3] = ring.MRed(x[3], d, qi, mredParams)
			z[4] = ring.MRed(x[4], d, qi, mredParams)
			z[5] = ring.MRed(x[5], d, qi, mredParams)
			z[6] = ring.MRed(x[6], d, qi, mredParams)
			z[7] = ring.MRed(x[7], d, qi, mredParams)
		}
	}
}

// ScaleDown transforms a Plaintext (R_q) into a PlaintextRingT (R_t) by scaling down the coefficient by t/Q and rounding.
func (encoder *mfvEncoder) ScaleDown(pt *Plaintext, ptRt *PlaintextRingT) {
	level := pt.Level()
	encoder.scalers[level].DivByQOverTRounded(pt.value, ptRt.value)
}

// RingTToMul transforms a PlaintextRingT into a PlaintextMul by operating the NTT transform
// of R_q and putting the coefficients in Montgomery form.
func (encoder *mfvEncoder) RingTToMul(ptRt *PlaintextRingT, ptMul *PlaintextMul) {
	if ptRt.value != ptMul.value {
		copy(ptMul.value.Coeffs[0], ptRt.value.Coeffs[0])
	}

	level := ptMul.Level()
	for i := 1; i < level+1; i++ {
		copy(ptMul.value.Coeffs[i], ptRt.value.Coeffs[0])
	}

	ringQ := encoder.ringQs[level]
	ringQ.NTTLazy(ptMul.value, ptMul.value)
	ringQ.MForm(ptMul.value, ptMul.value)
}

// MulToRingT transforms a PlaintextMul into PlaintextRingT by operating the inverse NTT transform of R_q and
// putting the coefficients out of the Montgomery form.
func (encoder *mfvEncoder) MulToRingT(pt *PlaintextMul, ptRt *PlaintextRingT) {
	level := pt.Level()
	ringQ := encoder.ringQs[level]
	ringQ.InvNTTLvl(0, pt.value, ptRt.value)
	ringQ.InvMFormLvl(0, ptRt.value, ptRt.value)
}

// DecodeRingT decodes any plaintext type into a PlaintextRingT. It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (encoder *mfvEncoder) DecodeRingT(p interface{}, ptRt *PlaintextRingT) {
	switch pt := p.(type) {
	case *Plaintext:
		encoder.ScaleDown(pt, ptRt)
	case *PlaintextMul:
		encoder.MulToRingT(pt, ptRt)
	case *PlaintextRingT:
		ptRt.Copy(pt.Element)
	default:
		panic(fmt.Errorf("unsupported plaintext type (%T)", pt))
	}
}

// DecodeUint decodes a any plaintext type and write the coefficients in coeffs. It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (encoder *mfvEncoder) DecodeUint(p interface{}, coeffs []uint64) {

	var ptRt *PlaintextRingT
	var isInRingT bool
	if ptRt, isInRingT = p.(*PlaintextRingT); !isInRingT {
		encoder.DecodeRingT(p, encoder.tmpPtRt)
		ptRt = encoder.tmpPtRt
	}

	encoder.ringT.NTT(ptRt.value, encoder.tmpPoly)

	// for i := 0; i < encoder.ringQ.N; i++ {
	for i := 0; i < encoder.params.N(); i++ {
		coeffs[i] = encoder.tmpPoly.Coeffs[0][encoder.indexMatrix[i]]
	}
}

// DecodeUintNew decodes any plaintext type and returns the coefficients in a new []uint64.
// It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (encoder *mfvEncoder) DecodeUintNew(p interface{}) (coeffs []uint64) {
	coeffs = make([]uint64, encoder.params.N())
	encoder.DecodeUint(p, coeffs)
	return
}

// DecodeInt decodes a any plaintext type and write the coefficients in coeffs. It also decodes the sign
// modulus (by centering the values around the plaintext). It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (encoder *mfvEncoder) DecodeInt(p interface{}, coeffs []int64) {

	encoder.DecodeRingT(p, encoder.tmpPtRt)

	encoder.ringT.NTT(encoder.tmpPtRt.value, encoder.tmpPoly)

	modulus := int64(encoder.params.t)
	modulusHalf := modulus >> 1
	var value int64
	for i := 0; i < encoder.params.N(); i++ {

		value = int64(encoder.tmpPoly.Coeffs[0][encoder.indexMatrix[i]])
		coeffs[i] = value
		if value >= modulusHalf {
			coeffs[i] -= modulus
		}
	}
}

// DecodeIntNew decodes any plaintext type and returns the coefficients in a new []int64. It also decodes the sign
// modulus (by centering the values around the plaintext). It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (encoder *mfvEncoder) DecodeIntNew(p interface{}) (coeffs []int64) {
	coeffs = make([]int64, encoder.params.N())
	encoder.DecodeInt(p, coeffs)
	return
}

func (encoder *mfvEncoder) EncodeDiagMatrixT(level int, diagMatrix map[int][]uint64, maxM1N2Ratio float64, logSlots int) (matrix *PtDiagMatrixT) {
	matrix = new(PtDiagMatrixT)
	matrix.LogSlots = logSlots
	slots := 1 << logSlots

	if len(diagMatrix) > 2 {
		// N1*N2 = N
		N1 := findbestbabygiantstepsplit(diagMatrix, slots, maxM1N2Ratio)
		matrix.N1 = N1

		index, _ := bsgsIndex(diagMatrix, slots, N1)

		matrix.Vec = make(map[int][2]*ring.Poly)

		for j := range index {
			for _, i := range index[j] {
				// manages inputs that have rotation between 0 and slots-1 or between -slots/2 and slots/2-1
				v := diagMatrix[N1*j+i]
				if len(v) == 0 {
					v = diagMatrix[(N1*j+i)-slots]
				}

				matrix.Vec[N1*j+i] = encoder.encodeDiagonalT(level, logSlots, rotateT(v, -N1*j))
			}
		}
	} else {
		matrix.Vec = make(map[int][2]*ring.Poly)

		for i := range diagMatrix {
			idx := i
			if idx < 0 {
				idx += slots
			}
			matrix.Vec[idx] = encoder.encodeDiagonalT(level, logSlots, diagMatrix[i])
		}

		matrix.naive = true
	}

	return
}

func (encoder *mfvEncoder) encodeDiagonalT(level int, logSlots int, m []uint64) [2]*ring.Poly {
	ringQ := encoder.ringQs[level]
	ringP := encoder.ringP
	ringT := encoder.ringT

	// EncodeUintRingT
	mT := ringT.NewPoly()
	for i := 0; i < len(m); i++ {
		mT.Coeffs[0][encoder.indexMatrix[i]] = m[i]
	}
	for i := len(m); i < len(encoder.indexMatrix); i++ {
		mT.Coeffs[0][encoder.indexMatrix[i]] = m[i%len(m)]
	}
	ringT.InvNTT(mT, mT)

	// RingTToMulRingQ
	mQ := ringQ.NewPoly()
	for i := 0; i < len(ringQ.Modulus); i++ {
		copy(mQ.Coeffs[i], mT.Coeffs[0])
	}
	ringQ.NTTLazy(mQ, mQ)
	ringQ.MForm(mQ, mQ)

	// RingTToMulRingP
	mP := ringP.NewPoly()
	for i := 0; i < len(encoder.ringP.Modulus); i++ {
		copy(mP.Coeffs[i], mT.Coeffs[0])
	}
	ringP.NTTLazy(mP, mP)
	ringP.MForm(mP, mP)

	return [2]*ring.Poly{mQ, mP}
}

func (encoder *mfvEncoder) GenSlotToCoeffMatFV() (pDcds [][]*PtDiagMatrixT) {
	params := encoder.params
	fullBatch := params.logSlots == params.logN
	depth := params.logSlots

	if fullBatch {
		depth += 1
	}

	modCount := len(params.qi)
	pDcds = make([][]*PtDiagMatrixT, modCount)

	for level := 0; level < modCount; level++ {
		pDcds[level] = make([]*PtDiagMatrixT, depth)
		pVecDcd := genDcdMats(params.logSlots, depth, params.t, fullBatch)

		for i := 0; i < len(pDcds[level]); i++ {
			pDcds[level][i] = encoder.EncodeDiagMatrixT(level, pVecDcd[i], 16.0, params.logSlots)
		}
	}

	return
}
