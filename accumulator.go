// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package accumulator implements a cryptographic accumulator.
// An accumulator is like a merkle tree but the proofs are constant size.
// This package is just a toy.
package accumulator

import (
	"crypto/rand"
	"io"
	"math/big"

	"golang.org/x/crypto/sha3"

	"vuvuzela.io/concurrency"
)

func HashToPrime(data []byte) *big.Int {
	// Unclear if this is a good hash function.
	h := sha3.NewShake256()
	h.Write(data)
	p, err := rand.Prime(h, 256)
	if err != nil {
		panic(err)
	}
	return p
}

// PrivateKey is the private key for an RSA accumulator.
type PrivateKey struct {
	P, Q    *big.Int
	N       *big.Int // N = P*Q
	Totient *big.Int // Totient = (P-1)*(Q-1)
}

type PublicKey struct {
	N *big.Int
}

var base = big.NewInt(65537)
var bigOne = big.NewInt(1)
var bigTwo = big.NewInt(2)

func GenerateKey(random io.Reader) (*PublicKey, *PrivateKey, error) {
	for {
		p, err := rand.Prime(random, 1024)
		if err != nil {
			return nil, nil, err
		}
		q, err := rand.Prime(random, 1024)
		if err != nil {
			return nil, nil, err
		}

		pminus1 := new(big.Int).Sub(p, bigOne)
		qminus1 := new(big.Int).Sub(q, bigOne)
		totient := new(big.Int).Mul(pminus1, qminus1)

		g := new(big.Int).GCD(nil, nil, base, totient)
		if g.Cmp(bigOne) == 0 {
			privateKey := &PrivateKey{
				P:       p,
				Q:       q,
				N:       new(big.Int).Mul(p, q),
				Totient: totient,
			}
			publicKey := &PublicKey{
				N: new(big.Int).Set(privateKey.N),
			}
			return publicKey, privateKey, nil
		}
	}
}

func (key *PrivateKey) Accumulate(items ...[]byte) (acc *big.Int, witnesses []*big.Int) {
	primes := make([]*big.Int, len(items))
	concurrency.ParallelFor(len(items), func(p *concurrency.P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			primes[i] = HashToPrime(items[i])
		}
	})

	exp := big.NewInt(1)
	for i := range primes {
		exp.Mul(exp, primes[i])
		exp.Mod(exp, key.Totient)
	}
	acc = new(big.Int).Exp(base, exp, key.N)

	witnesses = make([]*big.Int, len(items))
	concurrency.ParallelFor(len(items), func(p *concurrency.P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			inv := new(big.Int).ModInverse(primes[i], key.Totient)
			inv.Mul(exp, inv)
			inv.Mod(inv, key.Totient)
			witnesses[i] = new(big.Int).Exp(base, inv, key.N)
		}
	})

	return
}

func (key *PublicKey) Verify(acc *big.Int, witness *big.Int, item []byte) bool {
	c := HashToPrime(item)
	v := new(big.Int).Exp(witness, c, key.N)
	return acc.Cmp(v) == 0
}
