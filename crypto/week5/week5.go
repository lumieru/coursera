package main

import (
	"log"
	"math/big"
)

const B = 1048576 // 2^20

var hashtable map[string]int = make(map[string]int)

func main() {
	bigB := big.NewInt(B)
	p, success := new(big.Int).SetString("13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171", 10)
	if !success {
		log.Print("New p failed")
		return
	}

	g, success := new(big.Int).SetString("11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568", 10)
	if !success {
		log.Print("New g failed")
		return
	}

	h, success := new(big.Int).SetString("3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333", 10)
	if !success {
		log.Print("New h failed")
		return
	}

	invert_g := new(big.Int)
	invert_g.ModInverse(g, p)
	res := new(big.Int).Set(h)
	hashtable[res.String()] = 0
	for i := 1; i <= B; i++ {
		// calculate: h/(g^x1) % p
		if i%10000 == 0 {
			log.Print("i=", i)
		}

		res.Mul(res, invert_g)
		res.Mod(res, p)
		hashtable[res.String()] = i
	}

	look := big.NewInt(1)
	g_B := new(big.Int)
	g_B.Exp(g, bigB, p)
	for i := 0; i <= B; i++ {
		if i%10000 == 0 {
			log.Print("look i=", i)
		}

		x1, ok := hashtable[look.String()]
		if ok {
			x := new(big.Int)
			x.Mul(big.NewInt(int64(i)), bigB)
			x.Add(x, big.NewInt(int64(x1)))
			log.Printf("x1=%d, x0=%d, x=%s", x1, i, x.String())
			return
		}

		look.Mul(look, g_B)
		look.Mod(look, p)
	}

	log.Print("No result.")
}
