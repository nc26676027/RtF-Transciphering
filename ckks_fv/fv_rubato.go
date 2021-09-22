package ckks_fv

import (
	"fmt"

	"github.com/ldsec/lattigo/v2/ring"
	"golang.org/x/crypto/sha3"
)

type RubatoParam struct {
	Blocksize    int
	PlainModulus uint64
	NumRound     int
	Sigma        float64
}

const (
	RUBATO80S = iota
	RUBATO80M
	RUBATO80L
	RUBATO128S
	RUBATO128M
	RUBATO128L
	RUBATO192S
	RUBATO192M
	RUBATO192L
	RUBATO256S
	RUBATO256M
	RUBATO256L
)

var RubatoParams = []RubatoParam{
	{
		// RUBATO80S
		Blocksize:    16,
		PlainModulus: 0xffa0001,
		NumRound:     2,
		Sigma:        4.4282593124559027251334012652716387400820308059307747000917767,
	},
	{
		// RUBATO80M
		Blocksize:    36,
		PlainModulus: 0x3ee0001,
		NumRound:     2,
		Sigma:        0.99735570100358169484986514983595467118964657791233664416481457,
	},
	{
		// RUBATO80L
		Blocksize:    64,
		PlainModulus: 0x1fc0001,
		NumRound:     2,
		Sigma:        0.63830764864229228470391369589501098956137380986389545226548133,
	},
	{
		// RUBATO128S
		Blocksize:    16,
		PlainModulus: 0x7e00001,
		NumRound:     5,
		Sigma:        2.9920671030107450845495954495078640135689397337370099324944437,
	},
	{
		// RUBATO128M
		Blocksize:    36,
		PlainModulus: 0x7e0001,
		NumRound:     2,
		Sigma:        2.5133363665290258710216601775866057713979093763390883432953327,
	},
	{
		// RUBATO128L
		Blocksize:    64,
		PlainModulus: 0x3ee0001,
		NumRound:     2,
		Sigma:        1.0771441570838682304378543618228310448848183041453235756979997,
	},
	{
		// RUBATO192S
		Blocksize:    16,
		PlainModulus: 0xffa0001,
		NumRound:     7,
		Sigma:        5.9442399779813469013051962930222898402902936043575263992222949,
	},
	{
		// RUBATO192M
		Blocksize:    36,
		PlainModulus: 0x7e00001,
		NumRound:     4,
		Sigma:        3.0718555590910316201375846614947403872641114599699968640276289,
	},
	{
		// RUBATO192L
		Blocksize:    64,
		PlainModulus: 0x3ee0001,
		NumRound:     3,
		Sigma:        1.5558748935655874439657896337440892870558486615432451648971107,
	},
	{
		// RUBATO256S
		Blocksize:    16,
		PlainModulus: 0xffa0001,
		NumRound:     11,
		Sigma:        4.7873073648171921352793527192125824217103035739792158919911100,
	},
	{
		// RUBATO256M
		Blocksize:    36,
		PlainModulus: 0x7e00001,
		NumRound:     6,
		Sigma:        2.6729132786895989421976386015603585187882528288050622063617031,
	},
	{
		// RUBATO256L
		Blocksize:    64,
		PlainModulus: 0x7e00001,
		NumRound:     4,
		Sigma:        1.9947114020071633896997302996719093423792931558246732883296291,
	},
}

type MFVRubato interface {
	Crypt(nonce [][]byte, counter []byte, kCt []*Ciphertext, rubatoModDown []int) []*Ciphertext
	CryptNoModSwitch(nonce [][]byte, counter []byte, kCt []*Ciphertext) []*Ciphertext
	CryptAutoModSwitch(nonce [][]byte, counter []byte, kCt []*Ciphertext, noiseEstimator MFVNoiseEstimator) (res []*Ciphertext, rubatoModDown []int)
	Reset(nbInitModDown int)
	EncKey(key []uint64) (res []*Ciphertext)
}

type mfvRubato struct {
	blocksize     int
	numRound      int
	slots         int
	nbInitModDown int

	params    *Parameters
	encoder   MFVEncoder
	encryptor MFVEncryptor
	evaluator MFVEvaluator

	stCt []*Ciphertext
	mkCt []*Ciphertext
	rkCt []*Ciphertext   // Buffer for round key
	rc   [][][]uint64    // RoundConstants[round][state][slot]
	rcPt []*PlaintextMul // Buffer for round constants
	xof  []sha3.ShakeHash
}

func NewMFVRubato(blocksize int, numRound int, params *Parameters, encoder MFVEncoder, encryptor MFVEncryptor, evaluator MFVEvaluator, nbInitModDown int) MFVRubato {
	rubato := new(mfvRubato)

	rubato.blocksize = blocksize
	rubato.numRound = numRound
	rubato.slots = params.FVSlots()
	rubato.nbInitModDown = nbInitModDown

	rubato.params = params
	rubato.encoder = encoder
	rubato.encryptor = encryptor
	rubato.evaluator = evaluator

	rubato.stCt = make([]*Ciphertext, blocksize)
	rubato.mkCt = make([]*Ciphertext, blocksize)
	rubato.rkCt = make([]*Ciphertext, blocksize)
	rubato.rcPt = make([]*PlaintextMul, blocksize)
	rubato.xof = make([]sha3.ShakeHash, rubato.slots)

	rubato.rc = make([][][]uint64, rubato.numRound+1)
	for r := 0; r <= rubato.numRound; r++ {
		rubato.rc[r] = make([][]uint64, blocksize)
		for i := 0; i < blocksize; i++ {
			rubato.rc[r][i] = make([]uint64, rubato.slots)
		}
	}

	// Precompute Initial States
	state := make([]uint64, rubato.slots)

	for i := 0; i < blocksize; i++ {
		for j := 0; j < rubato.slots; j++ {
			state[j] = uint64(i + 1) // ic = 1, ..., blocksize
		}
		icPT := NewPlaintextFV(params)
		encoder.EncodeUintSmall(state, icPT)
		encryptor.EncryptNew(icPT)
		rubato.stCt[i] = encryptor.EncryptNew(icPT)
		if nbInitModDown > 0 {
			evaluator.ModSwitchMany(rubato.stCt[i], rubato.stCt[i], nbInitModDown)
		}
	}
	return rubato
}

func (rubato *mfvRubato) Reset(nbInitModDown int) {
	// Precompute Initial States
	rubato.nbInitModDown = nbInitModDown
	state := make([]uint64, rubato.slots)

	for i := 0; i < rubato.blocksize; i++ {
		for j := 0; j < rubato.slots; j++ {
			state[j] = uint64(i + 1) // ic = 1, ..., blocksize
		}
		icPT := NewPlaintextFV(rubato.params)
		rubato.encoder.EncodeUintSmall(state, icPT)
		rubato.encryptor.EncryptNew(icPT)
		rubato.stCt[i] = rubato.encryptor.EncryptNew(icPT)
		if nbInitModDown > 0 {
			rubato.evaluator.ModSwitchMany(rubato.stCt[i], rubato.stCt[i], nbInitModDown)
		}
	}
}

// Compute Round Constants
func (rubato *mfvRubato) init(nonce [][]byte, counter []byte) {
	slots := rubato.slots
	for i := 0; i < slots; i++ {
		rubato.xof[i] = sha3.NewShake256()
		rubato.xof[i].Write(nonce[i])
		rubato.xof[i].Write(counter)
	}

	for r := 0; r <= rubato.numRound; r++ {
		for i := 0; i < rubato.blocksize; i++ {
			for slot := 0; slot < slots; slot++ {
				rubato.rc[r][i][slot] = SampleZqx(rubato.xof[slot], rubato.params.PlainModulus())
			}
		}
	}

	for i := 0; i < rubato.blocksize; i++ {
		nbSwitch := rubato.mkCt[i].Level() - rubato.stCt[i].Level()
		if nbSwitch > 0 {
			rubato.evaluator.ModSwitchMany(rubato.mkCt[i], rubato.mkCt[i], nbSwitch)
		}
	}
}

func (rubato *mfvRubato) findBudgetInfo(noiseEstimator MFVNoiseEstimator) (maxInvBudget, minErrorBits int) {
	plainModulus := ring.NewUint(rubato.params.PlainModulus())
	maxInvBudget = 0
	minErrorBits = 0
	for i := 0; i < rubato.blocksize; i++ {
		invBudget := noiseEstimator.InvariantNoiseBudget(rubato.stCt[i])
		errorBits := rubato.params.LogQLvl(rubato.stCt[i].Level()) - plainModulus.BitLen() - invBudget

		if invBudget > maxInvBudget {
			maxInvBudget = invBudget
			minErrorBits = errorBits
		}
	}
	return
}

func (rubato *mfvRubato) modSwitchAuto(round int, noiseEstimator MFVNoiseEstimator, rubatoModDown []int) {
	lvl := rubato.stCt[0].Level()

	QiLvl := rubato.params.Qi()[:lvl+1]
	LogQiLvl := make([]int, lvl+1)
	for i := 0; i < lvl+1; i++ {
		tmp := ring.NewUint(QiLvl[i])
		LogQiLvl[i] = tmp.BitLen()
	}

	invBudgetOld, errorBitsOld := rubato.findBudgetInfo(noiseEstimator)
	nbModSwitch, targetErrorBits := 0, errorBitsOld
	for {
		targetErrorBits -= LogQiLvl[lvl-nbModSwitch]
		if targetErrorBits > 0 {
			nbModSwitch++
		} else {
			break
		}
	}
	if nbModSwitch != 0 {
		tmp := rubato.stCt[0].CopyNew().Ciphertext()
		rubato.evaluator.ModSwitchMany(rubato.stCt[0], rubato.stCt[0], nbModSwitch)
		invBudgetNew, _ := rubato.findBudgetInfo(noiseEstimator)

		if invBudgetOld-invBudgetNew > 3 {
			nbModSwitch--
		}
		rubato.stCt[0] = tmp
	}

	if nbModSwitch > 0 {
		rubatoModDown[round] = nbModSwitch
		for i := 0; i < rubato.blocksize; i++ {
			rubato.evaluator.ModSwitchMany(rubato.stCt[i], rubato.stCt[i], nbModSwitch)
			rubato.evaluator.ModSwitchMany(rubato.mkCt[i], rubato.mkCt[i], nbModSwitch)
		}

		invBudgetNew, errorBitsNew := rubato.findBudgetInfo(noiseEstimator)
		fmt.Printf("Rubato Round %d [Budget | Error] : [%v | %v] -> [%v | %v]\n", round, invBudgetOld, errorBitsOld, invBudgetNew, errorBitsNew)
		fmt.Printf("Rubato modDown : %v\n\n", rubatoModDown)
	}
}

func (rubato *mfvRubato) modSwitch(nbSwitch int) {
	if nbSwitch <= 0 {
		return
	}
	for i := 0; i < rubato.blocksize; i++ {
		rubato.evaluator.ModSwitchMany(rubato.stCt[i], rubato.stCt[i], nbSwitch)
		rubato.evaluator.ModSwitchMany(rubato.mkCt[i], rubato.mkCt[i], nbSwitch)
	}
}

// Compute ciphertexts without modulus switching
func (rubato *mfvRubato) CryptNoModSwitch(nonce [][]byte, counter []byte, kCt []*Ciphertext) []*Ciphertext {
	for i := 0; i < rubato.blocksize; i++ {
		rubato.mkCt[i] = kCt[i].CopyNew().Ciphertext()
	}
	rubato.init(nonce, counter)

	rubato.addRoundKey(0, false)
	for r := 1; r < rubato.numRound; r++ {
		rubato.linLayer()
		rubato.feistel()
		rubato.addRoundKey(r, false)
	}
	rubato.linLayer()
	rubato.feistel()
	rubato.linLayer()
	rubato.addRoundKey(rubato.numRound, true)
	return rubato.stCt
}

// Compute ciphertexts with automatic modulus switching
func (rubato *mfvRubato) CryptAutoModSwitch(nonce [][]byte, counter []byte, kCt []*Ciphertext, noiseEstimator MFVNoiseEstimator) ([]*Ciphertext, []int) {
	rubatoModDown := make([]int, rubato.numRound+1)
	rubatoModDown[0] = rubato.nbInitModDown
	for i := 0; i < rubato.blocksize; i++ {
		rubato.mkCt[i] = kCt[i].CopyNew().Ciphertext()
	}
	rubato.init(nonce, counter)

	rubato.addRoundKey(0, false)
	for r := 1; r < rubato.numRound; r++ {
		rubato.linLayer()
		rubato.feistel()
		rubato.modSwitchAuto(r, noiseEstimator, rubatoModDown)
		rubato.addRoundKey(r, false)
	}
	rubato.linLayer()
	rubato.feistel()
	rubato.modSwitchAuto(rubato.numRound, noiseEstimator, rubatoModDown)
	rubato.linLayer()
	rubato.addRoundKey(rubato.numRound, true)
	return rubato.stCt, rubatoModDown
}

// Compute ciphertexts with modulus switching as given in rubatoModDown
func (rubato *mfvRubato) Crypt(nonce [][]byte, counter []byte, kCt []*Ciphertext, rubatoModDown []int) []*Ciphertext {
	if rubatoModDown[0] != rubato.nbInitModDown {
		errorString := fmt.Sprintf("nbInitModDown expected %d but %d given", rubato.nbInitModDown, rubatoModDown[0])
		panic(errorString)
	}

	for i := 0; i < rubato.blocksize; i++ {
		rubato.mkCt[i] = kCt[i].CopyNew().Ciphertext()
	}
	rubato.init(nonce, counter)

	rubato.addRoundKey(0, false)
	for r := 1; r < rubato.numRound; r++ {
		rubato.linLayer()
		rubato.feistel()
		rubato.modSwitch(rubatoModDown[r])
		rubato.addRoundKey(r, false)
	}
	rubato.linLayer()
	rubato.feistel()
	rubato.modSwitch(rubatoModDown[rubato.numRound])
	rubato.linLayer()
	rubato.addRoundKey(rubato.numRound, true)
	return rubato.stCt
}

func (rubato *mfvRubato) addRoundKey(round int, reduce bool) {
	ev := rubato.evaluator

	for i := 0; i < rubato.blocksize; i++ {
		rubato.rcPt[i] = NewPlaintextMulLvl(rubato.params, rubato.stCt[i].Level())
		rubato.encoder.EncodeUintMulSmall(rubato.rc[round][i], rubato.rcPt[i])
	}

	for i := 0; i < rubato.blocksize; i++ {
		rubato.rkCt[i] = rubato.evaluator.MulNew(rubato.mkCt[i], rubato.rcPt[i])
	}

	for i := 0; i < rubato.blocksize; i++ {
		if reduce {
			ev.Add(rubato.stCt[i], rubato.rkCt[i], rubato.stCt[i])
		} else {
			ev.AddNoMod(rubato.stCt[i], rubato.rkCt[i], rubato.stCt[i])
		}
	}
}

func (rubato *mfvRubato) linLayer() {
	ev := rubato.evaluator
	buf := make([]*Ciphertext, rubato.blocksize)

	if rubato.blocksize == 16 {
		// MixColumns
		for col := 0; col < 4; col++ {
			sum := ev.AddNoModNew(rubato.stCt[col], rubato.stCt[col+4])
			ev.AddNoMod(sum, rubato.stCt[col+8], sum)
			ev.AddNoMod(sum, rubato.stCt[col+12], sum)

			for row := 0; row < 4; row++ {
				buf[row*4+col] = ev.AddNoModNew(sum, rubato.stCt[row*4+col])
				ev.AddNoMod(buf[row*4+col], rubato.stCt[((row+1)%4)*4+col], buf[row*4+col])
				ev.AddNoMod(buf[row*4+col], rubato.stCt[((row+1)%4)*4+col], buf[row*4+col])
				ev.Reduce(buf[row*4+col], buf[row*4+col])
			}
		}
		// MixRows
		for row := 0; row < 4; row++ {
			sum := ev.AddNoModNew(buf[4*row], buf[4*row+1])
			ev.AddNoMod(sum, buf[4*row+2], sum)
			ev.AddNoMod(sum, buf[4*row+3], sum)

			for col := 0; col < 4; col++ {
				rubato.stCt[row*4+col] = ev.AddNoModNew(sum, buf[row*4+col])
				ev.AddNoMod(rubato.stCt[row*4+col], buf[row*4+(col+1)%4], rubato.stCt[row*4+col])
				ev.AddNoMod(rubato.stCt[row*4+col], buf[row*4+(col+1)%4], rubato.stCt[row*4+col])
				ev.Reduce(rubato.stCt[row*4+col], rubato.stCt[row*4+col])
			}
		}
	} else if rubato.blocksize == 36 {
		// MixColumns
		for col := 0; col < 6; col++ {
			sum := ev.AddNoModNew(rubato.stCt[col], rubato.stCt[col+6])
			ev.AddNoMod(sum, rubato.stCt[col+12], sum)
			ev.AddNoMod(sum, rubato.stCt[col+18], sum)
			ev.AddNoMod(sum, rubato.stCt[col+24], sum)
			ev.AddNoMod(sum, rubato.stCt[col+30], sum)
			ev.Reduce(sum, sum)

			for row := 0; row < 6; row++ {
				buf[row*6+col] = ev.AddNoModNew(sum, rubato.stCt[row*6+col])
				ev.AddNoMod(buf[row*6+col], rubato.stCt[row*6+col], buf[row*6+col])
				ev.AddNoMod(buf[row*6+col], rubato.stCt[row*6+col], buf[row*6+col])
				ev.AddNoMod(buf[row*6+col], rubato.stCt[((row+1)%6)*6+col], buf[row*6+col])
				ev.Reduce(buf[row*6+col], buf[row*6+col])
				ev.AddNoMod(buf[row*6+col], rubato.stCt[((row+2)%6)*6+col], buf[row*6+col])
				ev.AddNoMod(buf[row*6+col], rubato.stCt[((row+2)%6)*6+col], buf[row*6+col])
				ev.AddNoMod(buf[row*6+col], rubato.stCt[((row+2)%6)*6+col], buf[row*6+col])
				ev.AddNoMod(buf[row*6+col], rubato.stCt[((row+3)%6)*6+col], buf[row*6+col])
				ev.AddNoMod(buf[row*6+col], rubato.stCt[((row+3)%6)*6+col], buf[row*6+col])
				ev.Reduce(buf[row*6+col], buf[row*6+col])
			}
		}
		// MixRows
		for row := 0; row < 6; row++ {
			sum := ev.AddNoModNew(buf[6*row], buf[6*row+1])
			ev.AddNoMod(sum, buf[6*row+2], sum)
			ev.AddNoMod(sum, buf[6*row+3], sum)
			ev.AddNoMod(sum, buf[6*row+4], sum)
			ev.AddNoMod(sum, buf[6*row+5], sum)
			ev.Reduce(sum, sum)

			for col := 0; col < 6; col++ {
				rubato.stCt[row*6+col] = ev.AddNoModNew(sum, buf[row*6+col])
				ev.AddNoMod(rubato.stCt[row*6+col], buf[row*6+col], rubato.stCt[row*6+col])
				ev.AddNoMod(rubato.stCt[row*6+col], buf[row*6+col], rubato.stCt[row*6+col])
				ev.AddNoMod(rubato.stCt[row*6+col], buf[row*6+(col+1)%6], rubato.stCt[row*6+col])
				ev.Reduce(buf[row*6+col], buf[row*6+col])
				ev.AddNoMod(rubato.stCt[row*6+col], buf[row*6+(col+2)%6], rubato.stCt[row*6+col])
				ev.AddNoMod(rubato.stCt[row*6+col], buf[row*6+(col+2)%6], rubato.stCt[row*6+col])
				ev.AddNoMod(rubato.stCt[row*6+col], buf[row*6+(col+2)%6], rubato.stCt[row*6+col])
				ev.AddNoMod(rubato.stCt[row*6+col], buf[row*6+(col+3)%6], rubato.stCt[row*6+col])
				ev.AddNoMod(rubato.stCt[row*6+col], buf[row*6+(col+3)%6], rubato.stCt[row*6+col])
				ev.Reduce(rubato.stCt[row*6+col], rubato.stCt[row*6+col])
			}
		}
	} else if rubato.blocksize == 64 {
		// MixColumns
		for col := 0; col < 8; col++ {
			sum := ev.AddNoModNew(rubato.stCt[col], rubato.stCt[col+8])
			ev.AddNoMod(sum, rubato.stCt[col+16], sum)
			ev.AddNoMod(sum, rubato.stCt[col+24], sum)
			ev.AddNoMod(sum, rubato.stCt[col+32], sum)
			ev.AddNoMod(sum, rubato.stCt[col+40], sum)
			ev.AddNoMod(sum, rubato.stCt[col+48], sum)
			ev.AddNoMod(sum, rubato.stCt[col+56], sum)
			ev.Reduce(sum, sum)

			for row := 0; row < 8; row++ {
				buf[row*8+col] = ev.AddNoModNew(sum, rubato.stCt[row*8+col])
				ev.AddNoMod(buf[row*8+col], rubato.stCt[row*8+col], buf[row*8+col])
				ev.AddNoMod(buf[row*8+col], rubato.stCt[row*8+col], buf[row*8+col])
				ev.AddNoMod(buf[row*8+col], rubato.stCt[row*8+col], buf[row*8+col])
				ev.Reduce(buf[row*8+col], buf[row*8+col])
				ev.AddNoMod(buf[row*8+col], rubato.stCt[((row+1)%8)*8+col], buf[row*8+col])
				ev.AddNoMod(buf[row*8+col], rubato.stCt[((row+1)%8)*8+col], buf[row*8+col])
				ev.AddNoMod(buf[row*8+col], rubato.stCt[((row+2)%8)*8+col], buf[row*8+col])
				ev.AddNoMod(buf[row*8+col], rubato.stCt[((row+2)%8)*8+col], buf[row*8+col])
				ev.AddNoMod(buf[row*8+col], rubato.stCt[((row+2)%8)*8+col], buf[row*8+col])
				ev.Reduce(buf[row*8+col], buf[row*8+col])
				ev.AddNoMod(buf[row*8+col], rubato.stCt[((row+3)%8)*8+col], buf[row*8+col])
				ev.AddNoMod(buf[row*8+col], rubato.stCt[((row+3)%8)*8+col], buf[row*8+col])
				ev.AddNoMod(buf[row*8+col], rubato.stCt[((row+4)%8)*8+col], buf[row*8+col])
				ev.AddNoMod(buf[row*8+col], rubato.stCt[((row+4)%8)*8+col], buf[row*8+col])
				ev.AddNoMod(buf[row*8+col], rubato.stCt[((row+4)%8)*8+col], buf[row*8+col])
				ev.Reduce(buf[row*8+col], buf[row*8+col])
				ev.AddNoMod(buf[row*8+col], rubato.stCt[((row+4)%8)*8+col], buf[row*8+col])
				ev.AddNoMod(buf[row*8+col], rubato.stCt[((row+4)%8)*8+col], buf[row*8+col])
				ev.AddNoMod(buf[row*8+col], rubato.stCt[((row+5)%8)*8+col], buf[row*8+col])
				ev.Reduce(buf[row*8+col], buf[row*8+col])
			}
		}
		// MixRows
		for row := 0; row < 8; row++ {
			sum := ev.AddNoModNew(buf[8*row], buf[8*row+1])
			ev.AddNoMod(sum, buf[8*row+2], sum)
			ev.AddNoMod(sum, buf[8*row+3], sum)
			ev.AddNoMod(sum, buf[8*row+4], sum)
			ev.AddNoMod(sum, buf[8*row+5], sum)
			ev.AddNoMod(sum, buf[8*row+6], sum)
			ev.AddNoMod(sum, buf[8*row+7], sum)
			ev.Reduce(sum, sum)

			for col := 0; col < 8; col++ {
				rubato.stCt[row*8+col] = ev.AddNoModNew(sum, buf[row*8+col])
				ev.AddNoMod(rubato.stCt[row*8+col], buf[row*8+col], rubato.stCt[row*8+col])
				ev.AddNoMod(rubato.stCt[row*8+col], buf[row*8+col], rubato.stCt[row*8+col])
				ev.AddNoMod(rubato.stCt[row*8+col], buf[row*8+col], rubato.stCt[row*8+col])
				ev.Reduce(rubato.stCt[row*8+col], rubato.stCt[row*8+col])
				ev.AddNoMod(rubato.stCt[row*8+col], buf[row*8+(col+1)%8], rubato.stCt[row*8+col])
				ev.AddNoMod(rubato.stCt[row*8+col], buf[row*8+(col+1)%8], rubato.stCt[row*8+col])
				ev.AddNoMod(rubato.stCt[row*8+col], buf[row*8+(col+2)%8], rubato.stCt[row*8+col])
				ev.AddNoMod(rubato.stCt[row*8+col], buf[row*8+(col+2)%8], rubato.stCt[row*8+col])
				ev.AddNoMod(rubato.stCt[row*8+col], buf[row*8+(col+2)%8], rubato.stCt[row*8+col])
				ev.Reduce(rubato.stCt[row*8+col], rubato.stCt[row*8+col])
				ev.AddNoMod(rubato.stCt[row*8+col], buf[row*8+(col+3)%8], rubato.stCt[row*8+col])
				ev.AddNoMod(rubato.stCt[row*8+col], buf[row*8+(col+3)%8], rubato.stCt[row*8+col])
				ev.AddNoMod(rubato.stCt[row*8+col], buf[row*8+(col+4)%8], rubato.stCt[row*8+col])
				ev.AddNoMod(rubato.stCt[row*8+col], buf[row*8+(col+4)%8], rubato.stCt[row*8+col])
				ev.AddNoMod(rubato.stCt[row*8+col], buf[row*8+(col+4)%8], rubato.stCt[row*8+col])
				ev.Reduce(rubato.stCt[row*8+col], rubato.stCt[row*8+col])
				ev.AddNoMod(rubato.stCt[row*8+col], buf[row*8+(col+4)%8], rubato.stCt[row*8+col])
				ev.AddNoMod(rubato.stCt[row*8+col], buf[row*8+(col+4)%8], rubato.stCt[row*8+col])
				ev.AddNoMod(rubato.stCt[row*8+col], buf[row*8+(col+5)%8], rubato.stCt[row*8+col])
				ev.Reduce(rubato.stCt[row*8+col], rubato.stCt[row*8+col])
			}
		}
	} else {
		panic("Invalid blocksize")
	}
}

func (rubato *mfvRubato) feistel() {
	ev := rubato.evaluator
	for i := rubato.blocksize - 1; i > 0; i-- {
		tmp := ev.MulNew(rubato.stCt[i-1], rubato.stCt[i-1])
		ev.Relinearize(tmp, tmp)
		ev.Add(rubato.stCt[i], tmp, rubato.stCt[i])
	}
}

func (rubato *mfvRubato) EncKey(key []uint64) (res []*Ciphertext) {
	slots := rubato.slots
	res = make([]*Ciphertext, rubato.blocksize)

	for i := 0; i < rubato.blocksize; i++ {
		dupKey := make([]uint64, slots)
		for j := 0; j < slots; j++ {
			dupKey[j] = key[i]
		}

		keyPt := NewPlaintextFV(rubato.params)
		rubato.encoder.EncodeUintSmall(dupKey, keyPt)
		res[i] = rubato.encryptor.EncryptNew(keyPt)
		if rubato.nbInitModDown > 0 {
			rubato.evaluator.ModSwitchMany(res[i], res[i], rubato.nbInitModDown)
		}
	}
	return
}
