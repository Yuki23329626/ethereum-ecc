package main

import (
	"crypto/rand"
	// "encoding/hex"
	"crypto/sha256"
	"fmt"
	"strconv"
	// "encoding/binary"
	"github.com/clearmatics/bn256"
	"math/big"
	// "reflect"
	// "encoding/binary"
)

// convert the string, which represents the hex value, into a bitInt
func Hex2Dec(input string) *big.Int {
	sum := big.NewInt(0)
	temp, _ := strconv.ParseInt(string(input[0]), 16, 32)
	sum = sum.Add(sum, big.NewInt(temp))
	for i:=1; i < len(input); i++ {
		sum = sum.Mul(sum, big.NewInt(16))
		temp, _ = strconv.ParseInt(string(input[i]), 16, 32)
		sum = sum.Add(sum, big.NewInt(temp))
	}
	return sum
}

// convert bigInt into 256-bit []int
func Big2Bits(input *big.Int) []int{
	temp := new(big.Int)
	temp = temp.Set(input)
	arr := make([]int, 256)
	i := 255
	for  temp.Cmp(big.NewInt(0)) == 1 {
		// fmt.Println(input)
		if( big.NewInt(0).Cmp(new(big.Int).Mod(temp, big.NewInt(2))) == 0 ){
			// fmt.Println("SHIT")
			arr[i] = 0
			temp.Div(temp, big.NewInt(2))
		} else {
			arr[i] = 1
			temp.Div(temp, big.NewInt(2))
		}
		i = i - 1
	}
	return arr
}

// convert 256-bit []int into bigInt
func Bits2Big(input []int) *big.Int{
	sum := big.NewInt(0)
	for i:=0; i < 256; i++ {
		sum.Mul(sum, big.NewInt(2))
		if( input[i] == 1 ){
			sum.Add(sum, big.NewInt(1))
		}
	}
	return sum
}

// Concatenate KW, TK, ri1 and ri3 to generate message inside Ci3
// Ci3 = (KW||TK||ri1||ri3) XOR H1(G1)
func concat1024Bits(a []int, b []int, c []int, d []int) []int{
	arr := make([]int, 1024)
	for i:=0; i < 256; i++ {
		arr[i] = a[i];
		arr[i+256*1] = b[i];
		arr[i+256*2] = c[i];
		arr[i+256*3] = d[i];
	}
	return arr
}

// xor operation (run through 1024 bits)
func Xor1024Bits(a []int, b[]int) []int{
	arr := make([]int, 1024)
	for i:=0; i < 1024; i++ {
		arr[i] = a[i]^b[i];
	}
	return arr
}

// H1 function: G1 -> {0,1}^(4λ)
func Hash1(data *bn256.G1) []int{
	byte32_H1 := sha256.Sum256([]byte(data.String()))
	byte_H1 := byte32_H1[:]
	bigInt_H1 := new(big.Int).SetBytes(byte_H1)
	H1_full := concat1024Bits(Big2Bits(bigInt_H1), Big2Bits(bigInt_H1), Big2Bits(bigInt_H1), Big2Bits(bigInt_H1))
	return H1_full
}

// H2 function: G2 X G1 X G1 -> Z_q^*
func Hash2(a *bn256.G2, b *bn256.G1, c *bn256.G1) *big.Int{
	str := a.String() + b.String() + c.String()
	byte32_H2 := sha256.Sum256([]byte(str))
	byte_H2 := byte32_H2[:]
	bigInt_H2 := new(big.Int).SetBytes(byte_H2)
	return bigInt_H2
}

func main() {

	// sk_j := big.NewInt(7)
	// fsk_oi := big.NewInt(8)

	// System initialization: public key and private key generation
	// Roles: 
	// sk_i for data owner u_i, fsk_oi shared by data owner u_i and oralce;
	// sk_j for data user u_j, fsk_oj shared by data user u_j and oralce;
	sk_i, _ := rand.Int(rand.Reader, bn256.Order)
	fsk_oi, _ := rand.Int(rand.Reader, bn256.Order)
	sk_j, _ := rand.Int(rand.Reader, bn256.Order)
	fsk_oj, _ := rand.Int(rand.Reader, bn256.Order)

	pk_i_1 := new(bn256.G1).ScalarBaseMult(sk_j)
	pk_i_2 := new(bn256.G2).ScalarBaseMult(sk_j)
	fpk_oi_1 := new(bn256.G1).ScalarBaseMult(fsk_oi)
	fpk_oi_2 := new(bn256.G2).ScalarBaseMult(fsk_oi)

	pk_j_1 := new(bn256.G1).ScalarBaseMult(sk_j)
	pk_j_2 := new(bn256.G2).ScalarBaseMult(sk_j)
	fpk_oj_1 := new(bn256.G1).ScalarBaseMult(fsk_oi)
	fpk_oj_2 := new(bn256.G2).ScalarBaseMult(fsk_oi)

	_ = sk_i
	_ = fsk_oi
	_ = sk_j
	_ = fsk_oj

	_ = pk_i_1
	_ = pk_i_2 
	_ = fpk_oi_1 
	_ = fpk_oi_2

	_ = pk_j_1
	_ = pk_j_2 
	_ = fpk_oj_1 
	_ = fpk_oj_2 

	// ri1 := big.NewInt(1)
	// ri2 := big.NewInt(3)
	// ri3 := big.NewInt(5)
	// rj1 := big.NewInt(2)
	// rj2 := big.NewInt(4)
	// rj3 := big.NewInt(6)

	// random parameters
	ri1, _ := rand.Int(rand.Reader, bn256.Order)
	ri2, _ := rand.Int(rand.Reader, bn256.Order)	
	ri3, _ := rand.Int(rand.Reader, bn256.Order)

	rj1, _ := rand.Int(rand.Reader, bn256.Order)
	rj2, _ := rand.Int(rand.Reader, bn256.Order)
	rj3, _ := rand.Int(rand.Reader, bn256.Order)

    KW := new(big.Int).SetBytes([]byte("keyword of traffic info."))
	// KW, _ := rand.Int(rand.Reader, bn256.Order)
	TK, _ := rand.Int(rand.Reader, bn256.Order)
	_ = KW
	_ = TK

	// ciphertext CT_i(KW) = {Ci1, Ci2, Ci3, D_KW, V_KW}
	Ci1 := new(bn256.G2).ScalarMult( new(bn256.G2).ScalarBaseMult(ri1), ri2)
	Ci2 := new(bn256.G1).Add(new(bn256.G1).ScalarMult(new(bn256.G1).ScalarMult(new(bn256.G1).ScalarBaseMult(KW), ri1), ri2), new(bn256.G1).ScalarBaseMult(ri3))

	Cj1 := new(bn256.G2).ScalarMult( new(bn256.G2).ScalarBaseMult(rj1), rj2)
	Cj2 := new(bn256.G1).Add(new(bn256.G1).ScalarMult(new(bn256.G1).ScalarMult(new(bn256.G1).ScalarBaseMult(KW), rj1), rj2), new(bn256.G1).ScalarBaseMult(rj3))

	bits_KW_i := concat1024Bits(Big2Bits(KW), Big2Bits(TK), Big2Bits(ri1), Big2Bits(ri3))
	bits_H1_i := Hash1(new(bn256.G1).ScalarMult(new(bn256.G1).ScalarMult(pk_i_1, fsk_oi), ri2))
	Ci3 := Xor1024Bits(bits_KW_i, bits_H1_i)
	_ = Ci3

	bits_KW_j := concat1024Bits(Big2Bits(KW), Big2Bits(TK), Big2Bits(rj1), Big2Bits(rj3))
	bits_H1_j := Hash1(new(bn256.G1).ScalarMult(new(bn256.G1).ScalarMult(pk_j_1, fsk_oj), rj2))
	Cj3 := Xor1024Bits(bits_KW_j, bits_H1_j)
	_ = Cj3

	V_KW := Hash2(Ci1, Ci2, new(bn256.G1).ScalarBaseMult(ri2))
	D_KW := new(big.Int).Sub( ri2, new(big.Int).Mul( V_KW, fsk_oi))
	_ = V_KW
	_ = D_KW

	// check if the original ri2 and the calculated ri2 can be matched
	// fmt.Println("V_KW:", V_KW)
	// fmt.Println("D_KW:", D_KW)
	// fmt.Println("ri2:", ri2)
	// fmt.Println("ri2:", new(big.Int).Add( D_KW, new(big.Int).Mul( V_KW, fsk_oi)))

	// Generating Trapdoor which is used in equality test

	Tioj := new(bn256.G1).Add( new(bn256.G1).ScalarMult( new(bn256.G1).ScalarMult( new(bn256.G1).ScalarMult(pk_j_1, fsk_oi), ri1), ri2), new(bn256.G1).Neg(new(bn256.G1).ScalarBaseMult(ri3)))
	Tjio := new(bn256.G1).Add( new(bn256.G1).ScalarMult( new(bn256.G1).ScalarMult( new(bn256.G1).ScalarMult(fpk_oi_1, sk_j), rj1), rj2), new(bn256.G1).Neg(new(bn256.G1).ScalarBaseMult(rj3)))
	_ = Ci1
	_ = Ci2
	_ = Cj1
	_ = Cj2
	_ = Tioj
	_ = Tjio

	// Intermediate Test Message

	TCi := new(bn256.G1).Add(Ci2, Tioj)
	TCj := new(bn256.G1).Add(Cj2, Tjio)
	_ = TCi
	_ = TCj

	fmt.Println("\n===== START : OURS matching parameters shown in BigInt=====")

	fmt.Println("[TCi.x, TCi.y, Cj1.x.re, Cj1.x.im, Cj1.y.re, Cj1.y.im,\nTCj.x, TCj.y, Ci1.x.re, Ci1.x.im, Ci1.y.re, Ci1.y.im]")
	fmt.Print("[",Hex2Dec(TCi.P.GetX()),",")
	fmt.Print(Hex2Dec(TCi.P.GetY()),",")

	fmt.Print(Hex2Dec(Cj1.P.GetXX()),",")
	fmt.Print(Hex2Dec(Cj1.P.GetXY()),",")
	fmt.Print(Hex2Dec(Cj1.P.GetYX()),",")
	fmt.Print(Hex2Dec(Cj1.P.GetYY()),",")

	fmt.Print(Hex2Dec(TCj.P.GetX()),",")
	fmt.Print(Hex2Dec(TCj.P.GetY()),",")

	fmt.Print(Hex2Dec(Ci1.P.GetXX()),",")
	fmt.Print(Hex2Dec(Ci1.P.GetXY()),",")
	fmt.Print(Hex2Dec(Ci1.P.GetYX()),",")
	fmt.Print(Hex2Dec(Ci1.P.GetYY()),"]")

	fmt.Println("\n===== END : OURS matching parameters shown in BigInt=====")

	fmt.Println("\n===== START : BPREET matching parameters shown in BigInt=====")
	fmt.Println("[Tioj.x, Tioj.y, Ci1.x.re, Ci1.x.im, Ci1.y.re, Ci1.y.im, Ci2.x, Ci2.y,\n Tjio.x, Tjio.y, Cj1.x.re, Cj1.x.im, Cj1.y.re, Cj1.y.im, Cㄨ2.x, Cj2.y]")
	fmt.Print("[",Hex2Dec(Tioj.P.GetX()),",")
	fmt.Print(Hex2Dec(Tioj.P.GetY()),",")

	fmt.Print(Hex2Dec(Ci1.P.GetXX()),",")
	fmt.Print(Hex2Dec(Ci1.P.GetXY()),",")
	fmt.Print(Hex2Dec(Ci1.P.GetYX()),",")
	fmt.Print(Hex2Dec(Ci1.P.GetYY()),",")

	fmt.Print(Hex2Dec(Ci2.P.GetX()),",")
	fmt.Print(Hex2Dec(Ci2.P.GetY()),",")

	fmt.Print(Hex2Dec(Tjio.P.GetX()),",")
	fmt.Print(Hex2Dec(Tjio.P.GetY()),",")

	fmt.Print(Hex2Dec(Cj1.P.GetXX()),",")
	fmt.Print(Hex2Dec(Cj1.P.GetXY()),",")
	fmt.Print(Hex2Dec(Cj1.P.GetYX()),",")
	fmt.Print(Hex2Dec(Cj1.P.GetYY()),",")
	
	fmt.Print(Hex2Dec(Cj2.P.GetX()),",")
	fmt.Print(Hex2Dec(Cj2.P.GetY()),"]")

	fmt.Println("\n===== END : BPREET matching parameters shown in BigInt=====")

	// Interest Matching:

	// Equality test
	e1 := bn256.Pair(TCi, Cj1)
	e2 := bn256.Pair(TCj, Ci1)
	_ = e1
	_ = e2
	fmt.Println("\nEquality test via bilinear pairing:")
	fmt.Println("(TCi,Ci1) from data owner, (TCj,Cj1) from data user")
	fmt.Println("e(TCi, Cj1) == e(TCj, Ci1):", e1.String() == e2.String())

	// Rekey generation
	rk_ioj := Xor1024Bits( Hash1( new(bn256.G1).ScalarMult( new(bn256.G1).ScalarMult(pk_i_1, fsk_oi), ri2)), Hash1( new(bn256.G1).ScalarMult( pk_j_1, ri2)))
	_ = rk_ioj
	
	// fmt.Println("\n===== START : BPREET reEncrypt parameters shown in Bits=====")

	// fmt.Print("Ci3 in Bits: \n[")
	// for i:=0; i<1023; i++ {
	// 	if( i%64==0 && i>1 ){
	// 		fmt.Print("\n")
	// 	}
	// 	fmt.Print(Ci3[i],",")
	// }
	// fmt.Print(Ci3[1023],"]\n")
	
	// fmt.Print("\nrk_ioj in Bits: \n[")
	// for i:=0; i<1023; i++ {
	// 	if( i%64==0 && i>1 ){
	// 		fmt.Print("\n")
	// 	}
	// 	fmt.Print(rk_ioj[i],",")
	// }
	// fmt.Print(rk_ioj[1023],"]\n")

	// fmt.Println("===== END : BPREET reEncrypt parameters shown in Bits =====\n")

	// ReEncrypt
	RCT_j_Cj3 := Xor1024Bits(Ci3, rk_ioj)

	// the decrypted message content will be {KW||TK||ri1||ri3}
	// each of the segment will be 256 bit: {256-bit||256-bit||256-bit||256-bit}
	decrypted_message := Xor1024Bits(RCT_j_Cj3, Hash1(new(bn256.G1).ScalarMult(new(bn256.G1).ScalarBaseMult(ri2), sk_j)))

	// show the KW value in BigInt
	// fmt.Println("KW in BigInt:",Bits2Big(decrypted_message[0:256]))
	fmt.Println("\nOriginal KW:\t", string(KW.Bytes()))
	fmt.Println("Decrypted KW:\t",string(Bits2Big(decrypted_message[0:256]).Bytes()))

}
