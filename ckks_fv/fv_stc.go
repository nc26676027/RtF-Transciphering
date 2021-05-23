package ckks_fv

import (
	"github.com/ldsec/lattigo/v2/ring"
)

func (ev *fvEvaluator) SlotsToCoeffs(ct *Ciphertext) *Ciphertext {
	sz := len(ev.pDcd)
	for i := 0; i < sz-2; i++ {
		ct = ev.LinearTransform(ct, ev.pDcd[i])[0]
	}
	tmp := ev.RotateRowsNew(ct)

	ct0 := ev.LinearTransform(ct, ev.pDcd[sz-2])[0]
	ct1 := ev.LinearTransform(tmp, ev.pDcd[sz-1])[0]

	ct = ev.AddNew(ct0, ct1)
	_, _, _, _ = tmp, ct0, ct1, ct

	return ct
}

func (params *Parameters) GenSlotToCoeffMatFV(encoder Encoder) (pDcd []*PtDiagMatrixT) {
	pDcd = make([]*PtDiagMatrixT, params.logSlots+1)
	pVecDcd := genDcdMats(params.logN, params.logSlots, params.t)

	for i := 0; i < len(pDcd); i++ {
		pDcd[i] = encoder.EncodeDiagMatrixT(pVecDcd[i], 16.0, params.logSlots)
	}

	return
}

func genDcdMats(logN, logSlots int, t uint64) (plainVector []map[int][]uint64) {
	// var nttLevel, depth, nextnttLevel int

	plainVector = make([]map[int][]uint64, logSlots+1)
	roots := computePrimitiveRoots(1<<(logSlots+1), t)
	diabMats := genDcdDiabDecomp(logSlots, roots)
	for i := 0; i < logSlots+1; i++ {
		// First layer of the i-th level of the NTT
		plainVector[i] = diabMats[i]
	}

	/*
		// We compute the chain of merge in order or reverse order depending if its DFT or InvDFT because
		// the way the levels are collapsed has an inpact on the total number of rotations and keys to be
		// stored. Ex. instead of using 255 + 64 plaintext vectors, we can use 127 + 128 plaintext vectors
		// by reversing the order of the merging.
		merge := make([]int, maxDepth)
		for i := 0; i < maxDepth; i++ {
			depth = int(math.Ceil(float64(nttLevel) / float64(maxDepth-i)))
			merge[len(merge)-i-1] = depth
			nttLevel -= depth
		}

		nttLevel = 0
		for i := 0; i < maxDepth; i++ {
			// First layer of the i-th level of the NTT
			plainVector[i] = diabMats[nttLevel]

			// Merges the layer with the next levels of the NTT if the total depth requires it.
			nextnttLevel = nttLevel + 1
			for j := 0; j < merge[i]-1; j++ {
				plainVector[i] = multDiabMats(diabMats[nextnttLevel], plainVector[i], logSlots, t)
				nextnttLevel++
			}

			nttLevel += merge[i]
		}
	*/

	return
}

func genDcdDiabDecomp(logN int, roots []uint64) (res []map[int][]uint64) {
	N := 1 << logN
	M := 2 * N
	pow5 := make([]int, M)
	res = make([]map[int][]uint64, logN+1)

	for i, exp5 := 0, 1; i < N; i, exp5 = i+1, exp5*5%M {
		pow5[i] = exp5
	}
	res[0] = make(map[int][]uint64)
	res[0][0] = make([]uint64, N)
	res[0][1] = make([]uint64, N)
	res[0][N/2-1] = make([]uint64, N)
	for i := 0; i < N; i += 2 {
		res[0][0][i] = 1
		res[0][0][i+1] = roots[3*N/2]
		res[0][1][i] = roots[N/2]
		res[0][N/2-1][i+1] = 1
	}

	for ind := 1; ind < logN-1; ind++ {
		s := 1 << (ind - 1) // size of each diabMat
		gap := N / s / 4

		res[ind] = make(map[int][]uint64)
		for _, rot := range []int{0, s, 2 * s, N/2 - s, N/2 - 2*s} {
			if res[ind][rot] == nil {
				res[ind][rot] = make([]uint64, N)
			}
		}

		for i := 0; i < N; i += 4 * s {
			/*
				[I 0 W0 0 ]
				[I 0 W1 0 ]
				[0 I 0 W0-]
				[0 I 0 W1-]
			*/
			for j := 0; j < s; j++ {
				res[ind][2*s][i+j] = roots[pow5[j]*gap%M]     // W0
				res[ind][s][i+s+j] = roots[pow5[s+j]*gap%M]   // W1
				res[ind][s][i+2*s+j] = roots[M-pow5[j]*gap%M] // W0-
				res[ind][0][i+j] = 1
				res[ind][0][i+3*s+j] = roots[M-pow5[s+j]*gap%M] // W1-
				res[ind][N/2-s][i+s+j] = 1
				res[ind][N/2-s][i+2*s+j] = 1
				res[ind][N/2-2*s][i+3*s+j] = 1
			}
		}
	}

	s := N / 4

	res[logN-1] = make(map[int][]uint64)
	res[logN-1][0] = make([]uint64, N)
	res[logN-1][s] = make([]uint64, N)

	res[logN] = make(map[int][]uint64)
	res[logN][0] = make([]uint64, N)
	res[logN][s] = make([]uint64, N)

	for i := 0; i < s; i++ {
		res[logN-1][0][i] = 1
		res[logN-1][0][i+3*s] = roots[M-pow5[s+i]%M]
		res[logN-1][s][i+s] = 1
		res[logN-1][s][i+2*s] = roots[M-pow5[i]%M]

		res[logN][0][i] = roots[pow5[i]%M]
		res[logN][0][i+3*s] = 1
		res[logN][s][i+s] = roots[pow5[s+i]%M]
		res[logN][s][i+2*s] = 1
	}
	return
}

func genDcdDiabDecompPart(logN, logSlots int, roots []uint64) (res []map[int][]uint64) {
	N := 1 << logN
	n := 1 << logSlots
	m := 2 * n
	pow5 := make([]int, m)
	res = make([]map[int][]uint64, logSlots+1)

	for i, exp5 := 0, 1; i < n; i, exp5 = i+1, exp5*5%m {
		pow5[i] = exp5
	}
	res[0] = make(map[int][]uint64)
	res[0][0] = make([]uint64, N)
	res[0][1] = make([]uint64, N)
	res[0][N/2-1] = make([]uint64, N)
	for i := 0; i < n; i += 2 {
		res[0][0][i] = 1
		res[0][0][i+1] = roots[3*n/2]
		res[0][1][i] = roots[n/2]
		res[0][N/2-1][i+1] = 1
	}

	for ind := 1; ind < logSlots-1; ind++ {
		s := 1 << (ind - 1) // size of each diabMat
		gap := n / s / 4

		res[ind] = make(map[int][]uint64)
		for _, rot := range []int{0, s, 2 * s, N/2 - s, N/2 - 2*s} {
			if res[ind][rot] == nil {
				res[ind][rot] = make([]uint64, N)
			}
		}

		for i := 0; i < n; i += 4 * s {
			/*
				[I 0 W0 0 ]
				[I 0 W1 0 ]
				[0 I 0 W0-]
				[0 I 0 W1-]
			*/
			for j := 0; j < s; j++ {
				res[ind][2*s][i+j] = roots[pow5[j]*gap%m]     // W0
				res[ind][s][i+s+j] = roots[pow5[s+j]*gap%m]   // W1
				res[ind][s][i+2*s+j] = roots[m-pow5[j]*gap%m] // W0-
				res[ind][0][i+j] = 1
				res[ind][0][i+3*s+j] = roots[m-pow5[s+j]*gap%m] // W1-
				res[ind][N/2-s][i+s+j] = 1
				res[ind][N/2-s][i+2*s+j] = 1
				res[ind][N/2-2*s][i+3*s+j] = 1
			}
		}
	}

	s := n / 4

	if n != N {
		res[logSlots-1] = make(map[int][]uint64)
		res[logSlots-1][0] = make([]uint64, N)
		res[logSlots-1][s] = make([]uint64, N)
		res[logSlots-1][2*s] = make([]uint64, N)
		res[logSlots-1][N/2-s] = make([]uint64, N)
		res[logSlots] = make(map[int][]uint64)
		res[logSlots][0] = make([]uint64, N)
		res[logSlots][s] = make([]uint64, N)
		res[logSlots][2*s] = make([]uint64, N)
		res[logSlots][N/2-s] = make([]uint64, N)

		for i := 0; i < s; i++ {
			res[logSlots-1][0][i] = 1
			res[logSlots-1][s][i+s] = roots[pow5[s+i]%m]
			res[logSlots-1][2*s][i] = roots[pow5[i]%m]
			res[logSlots-1][N/2-s][i+s] = 1

			res[logSlots][0][N/2+i] = 1
			res[logSlots][s][N/2+i+s] = roots[m-pow5[s+i]%m]
			res[logSlots][2*s][N/2+i] = roots[m-pow5[i]%m]
			res[logSlots][N/2-s][N/2+i+s] = 1
		}
	} else {
		res[logSlots-1] = make(map[int][]uint64)
		res[logSlots-1][0] = make([]uint64, N)
		res[logSlots-1][s] = make([]uint64, N)

		res[logSlots] = make(map[int][]uint64)
		res[logSlots][0] = make([]uint64, N)
		res[logSlots][s] = make([]uint64, N)

		for i := 0; i < s; i++ {
			res[logSlots-1][0][i] = 1
			res[logSlots-1][0][i+3*s] = roots[m-pow5[s+i]%m]
			res[logSlots-1][s][i+s] = 1
			res[logSlots-1][s][i+2*s] = roots[m-pow5[i]%m]

			res[logSlots][0][i] = roots[pow5[i]%m]
			res[logSlots][0][i+3*s] = 1
			res[logSlots][s][i+s] = roots[pow5[s+i]%m]
			res[logSlots][s][i+2*s] = 1
		}
	}
	return
}

func multDiabMats(A, B map[int][]uint64, logSlots int, t uint64) (C map[int][]uint64) {
	N := 1 << logSlots
	C = make(map[int][]uint64)

	for rotA, diagA := range A {
		for rotB, diagB := range B {
			rotC := (rotA + rotB) % N
			if C[rotC] == nil {
				C[rotC] = make([]uint64, N)
			}

			for i := 0; i < N; i++ {
				// C'[i][i+rotC] += A'[i][i+rotA] * B'[i+rotA][i+rotA+rotB]
				C[rotC][i] += diagA[i] * diagB[(rotA+i)%N]
				C[rotC][i] %= t
			}
		}
	}
	return
}

// compute M-th root of unity
func computePrimitiveRoots(M int, t uint64) (roots []uint64) {
	g := ring.PrimitiveRoot(t)
	w := ring.ModExp(g, (int(t)-1)/M, t)

	roots = make([]uint64, M)
	roots[0] = 1
	for i := 1; i < M; i++ {
		roots[i] = (roots[i-1] * w) % t
	}
	return
}
