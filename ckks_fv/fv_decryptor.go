package ckks_fv

import (
	"github.com/ldsec/lattigo/v2/ring"
)

// FVDecryptor is an interface for decryptors
type FVDecryptor interface {
	// DecryptNew decrypts the input ciphertext and returns the result on a new
	// plaintext.
	DecryptNew(ciphertext *Ciphertext) *Plaintext

	// Decrypt decrypts the input ciphertext and returns the result on the
	// provided receiver plaintext.
	Decrypt(ciphertext *Ciphertext, plaintext *Plaintext)
}

// fvDecryptor is a structure used to decrypt ciphertexts. It stores the secret-key.
type fvDecryptor struct {
	params   *Parameters
	ringQ    *ring.Ring
	sk       *SecretKey
	polypool *ring.Poly
}

// NewFVDecryptor creates a new Decryptor from the parameters with the secret-key
// given as input.
func NewFVDecryptor(params *Parameters, sk *SecretKey) FVDecryptor {

	var ringQ *ring.Ring
	var err error
	if ringQ, err = ring.NewRing(params.N(), params.qi); err != nil {
		panic(err)
	}

	return &fvDecryptor{
		params:   params.Copy(),
		ringQ:    ringQ,
		sk:       sk,
		polypool: ringQ.NewPoly(),
	}
}

func (decryptor *fvDecryptor) DecryptNew(ciphertext *Ciphertext) *Plaintext {
	p := NewPlaintextFV(decryptor.params)
	decryptor.Decrypt(ciphertext, p)
	return p
}

func (decryptor *fvDecryptor) Decrypt(ciphertext *Ciphertext, p *Plaintext) {

	ringQ := decryptor.ringQ
	tmp := decryptor.polypool

	ringQ.NTTLazy(ciphertext.value[ciphertext.Degree()], p.value)

	for i := ciphertext.Degree(); i > 0; i-- {
		ringQ.MulCoeffsMontgomery(p.value, decryptor.sk.Value, p.value)
		ringQ.NTTLazy(ciphertext.value[i-1], tmp)
		ringQ.Add(p.value, tmp, p.value)

		if i&3 == 3 {
			ringQ.Reduce(p.value, p.value)
		}
	}

	if (ciphertext.Degree())&3 != 3 {
		ringQ.Reduce(p.value, p.value)
	}

	ringQ.InvNTT(p.value, p.value)
}
