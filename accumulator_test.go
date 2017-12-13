// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package accumulator

import (
	"crypto/rand"
	"testing"
)

func TestAccumulator(t *testing.T) {
	publicKey, privateKey, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	items := makeItems(100)
	acc, witnesses := privateKey.Accumulate(items...)

	badItem := make([]byte, 32)
	rand.Read(badItem)

	for i, w := range witnesses {
		if !publicKey.Verify(acc, w, items[i]) {
			t.Fatal("item not found")
		}
		if publicKey.Verify(acc, w, badItem) {
			t.Fatal("bad item was verified")
		}
		if publicKey.Verify(acc, w, items[(i+1)%len(items)]) {
			t.Fatal("bad item was verified")
		}
	}
}

func makeItems(count int) [][]byte {
	items := make([][]byte, count)
	for i := range items {
		items[i] = make([]byte, 32)
		rand.Read(items[i])
	}
	return items
}

func benchAccumulate(b *testing.B, count int) {
	_, privateKey, err := GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	items := makeItems(count)
	b.ResetTimer()
	b.SetBytes(int64(count) * 32)

	for i := 0; i < b.N; i++ {
		privateKey.Accumulate(items...)
	}
}

func BenchmarkAccumulate100(b *testing.B) {
	benchAccumulate(b, 100)
}

func BenchmarkAccumulate1000(b *testing.B) {
	benchAccumulate(b, 1000)
}

func BenchmarkAccumulate10000(b *testing.B) {
	benchAccumulate(b, 10000)
}
