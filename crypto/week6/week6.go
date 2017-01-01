package main

import (
	"fmt"
	"github.com/cznic/mathutil"
	"math/big"
)

const B = 1048576 // 2^20

func main() {
	bigN, p, q := c1()
	c2()
	c3()
	c4(bigN, p, q)
}

func c1() (*big.Int, *big.Int, *big.Int) {
	strN := "179769313486231590772930519078902473361797697894230657273430081157732675805505620686985379449212982959585501387537164015710139858647833778606925583497541085196591615128057575940752635007475935288710823649949940771895617054361149474865046711015101563940680527540071584560878577663743040086340742855278549092581"
	bigN, res := new(big.Int).SetString(strN, 10)
	if !res {
		fmt.Print("c1.New big.Int failed\n")
		return nil, nil, nil
	}

	A := ceilSqrt(bigN)

	x := new(big.Int)
	x.Mul(A, A)
	x.Sub(x, bigN)
	x = mathutil.SqrtBig(x)

	p := new(big.Int)
	p.Sub(A, x)

	q := new(big.Int)
	q.Add(A, x)

	if verify(bigN, p, q) {
		fmt.Printf("c1:\np=%s\nq=%s\n", p.String(), q.String())
	} else {
		fmt.Print("c1 is wrong\n")
	}

	return bigN, p, q
}

func c2() {
	strN := "648455842808071669662824265346772278726343720706976263060439070378797308618081116462714015276061417569195587321840254520655424906719892428844841839353281972988531310511738648965962582821502504990264452100885281673303711142296421027840289307657458645233683357077834689715838646088239640236866252211790085787877"
	bigN, res := new(big.Int).SetString(strN, 10)
	if !res {
		fmt.Print("c2.New big.Int failed\n")
		return
	}

	//search A
	A := ceilSqrt(bigN)
	bigOne := big.NewInt(1)
	x := new(big.Int)
	p := new(big.Int)
	q := new(big.Int)
	for i := 0; i <= B; i++ {
		if i%10000 == 0 {
			fmt.Printf("c2 look i=%d\n", i)
		}

		x.Mul(A, A)
		x.Sub(x, bigN)
		x = mathutil.SqrtBig(x)

		p.Sub(A, x)

		q.Add(A, x)

		if verify(bigN, p, q) {
			fmt.Printf("c2:\np=%s\nq=%s\n", p.String(), q.String())
			return
		} else {
			A.Add(A, bigOne)
		}
	}

	fmt.Print("C2 not found\n")
}

func c3() {
	strN := "720062263747350425279564435525583738338084451473999841826653057981916355690188337790423408664187663938485175264994017897083524079135686877441155132015188279331812309091996246361896836573643119174094961348524639707885238799396839230364676670221627018353299443241192173812729276147530748597302192751375739387929"
	bigN, res := new(big.Int).SetString(strN, 10)
	if !res {
		fmt.Print("c3.New big.Int failed\n")
		return
	}

	// A = (3p+2q)/2不是整数，所以要算2A, 因为A=sqrt(6N), 所以2A=sqrt(24N)

	N24 := new(big.Int)
	N24.Mul(big.NewInt(24), bigN)
	A2 := ceilSqrt(N24)

	// -3/2*p^2+A*p-N=0, q=A-3/2p
	root := new(big.Int)
	root.Mul(A2, A2)
	root.Sub(root, N24)
	root = mathutil.SqrtBig(root)

	big6 := big.NewInt(6)
	big4 := big.NewInt(4)
	p := new(big.Int)
	p.Sub(A2, root)
	p.Div(p, big6)

	q := new(big.Int)
	q.Add(A2, root)
	q.Div(q, big4)

	if verify(bigN, p, q) {
		fmt.Printf("c3:first\np=%s\nq=%s\n", p.String(), q.String())
	} else {
		p.Add(A2, root)
		p.Div(p, big6)

		q.Sub(A2, root)
		q.Div(q, big4)

		if verify(bigN, p, q) {
			fmt.Printf("c3:second\np=%s\nq=%s\n", p.String(), q.String())
		} else {
			fmt.Print("c3 error\n")
		}
	}
}

func c4(bigN, p, q *big.Int) {
	strN := "22096451867410381776306561134883418017410069787892831071731839143676135600120538004282329650473509424343946219751512256465839967942889460764542040581564748988013734864120452325229320176487916666402997509188729971690526083222067771600019329260870009579993724077458967773697817571267229951148662959627934791540"
	CT, res := new(big.Int).SetString(strN, 10)
	if !res {
		fmt.Print("c4.New big.Int failed\n")
		return
	}

	bige := big.NewInt(65537)
	bigOne := big.NewInt(1)
	phiN := new(big.Int)
	phiN.Sub(bigN, p)
	phiN.Sub(phiN, q)
	phiN.Add(phiN, bigOne)

	d := new(big.Int)
	d.ModInverse(bige, phiN)

	pkcs1 := new(big.Int)
	pkcs1.Exp(CT, d, bigN)
	ptBytes := pkcs1.Bytes()
	// 0x02
	if ptBytes[0] != 2 {
		fmt.Print("c4 wrong\n")
		return
	}

	for i := 1; i < len(ptBytes); i++ {
		// look for 0
		if ptBytes[i] == 0 {
			fmt.Printf("c4: %s\n", ptBytes[i+1:])
			return
		}
	}

	fmt.Print("c4 wrong\n")
}

func ceilSqrt(bi *big.Int) *big.Int {
	res := mathutil.SqrtBig(bi)
	newBi := new(big.Int).Set(res)
	newBi.Mul(newBi, res)
	if newBi.String() == bi.String() {
		return res
	} else {
		return res.Add(res, big.NewInt(1))
	}

}

func verify(N, p, q *big.Int) bool {
	pq := new(big.Int)
	pq.Mul(p, q)

	if pq.String() == N.String() {
		return true
	} else {
		return false
	}
}
