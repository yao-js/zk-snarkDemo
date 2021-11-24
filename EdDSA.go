package main

import (
	crand "crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	edwardsbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	edd "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type eddsaCircuit struct {
	PublicKey eddsa.PublicKey   `gnark:",public"`
	Signature eddsa.Signature   `-`
	Message   frontend.Variable `gnark:",public"`
}

func (circuit *eddsaCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {

	params, err := twistededwards.NewEdCurve(curveID)
	if err != nil {
		return err
	}
	circuit.PublicKey.Curve = params

	// verify the signature in the cs
	eddsa.Verify(cs, circuit.Signature, circuit.Message, circuit.PublicKey)

	return nil
}

func main() {

	// instantiate hash function
	hFunc := hash.MIMC_BN254.New("seed")

	// create a eddsa key pair
	privateKey, _ := edd.GenerateKey(crand.Reader)
	publicKey := privateKey.Public()
	fmt.Println(len(publicKey.Bytes()))
	// note that the message is on 4 bytes
	msg := []byte("dads")

	// sign the message
	signature, _ := privateKey.Sign(msg, hFunc)
	// verifies signature
	isValid, _ := publicKey.Verify(signature, msg, hFunc)
	if !isValid {
		fmt.Println("1. invalid signature")
	} else {
		fmt.Println("1. valid signature")
	}

	// 开始编译电路circuit
	var circuit eddsaCircuit
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)

	pk, vk, _ := groth16.Setup(r1cs)

	// declare the witness
	var witness eddsaCircuit

	// assign message value
	witness.Message.Assign(msg)

	// public key bytes
	_publicKey := publicKey.Bytes()

	// temporary point
	var p edwardsbn254.PointAffine

	// assign public key values
	p.SetBytes(_publicKey[:32])
	axb := p.X.Bytes()
	ayb := p.Y.Bytes()
	witness.PublicKey.A.X.Assign(axb[:])
	witness.PublicKey.A.Y.Assign(ayb[:])

	// assign signature values
	p.SetBytes(signature[:32])
	rxb := p.X.Bytes()
	ryb := p.Y.Bytes()
	witness.Signature.R.X.Assign(rxb[:])
	witness.Signature.R.Y.Assign(ryb[:])

	// The S part of the signature is a 32 bytes scalar stored in signature[32:64].
	// As decribed earlier, we split is in S1, S2 such that S = 2^128*S1+S2 to prevent
	// overflowing the underlying representation in the circuit.
	witness.Signature.S1.Assign(signature[32:48])
	witness.Signature.S2.Assign(signature[48:])

	//newMsg := []byte("dsads")

	var publicWitness eddsaCircuit

	//publicWitness.Message.Assign(msg)

	var p2 edwardsbn254.PointAffine

	p2.SetBytes(_publicKey[:32])
	axb2 := p2.X.Bytes()
	ayb2 := p2.Y.Bytes()
	publicWitness.PublicKey.A.X.Assign(axb2[:])
	publicWitness.PublicKey.A.Y.Assign(ayb2[:])
	// assign signature values
	//p2.SetBytes(signature[:32])
	//rxb2 := p2.X.Bytes()
	//ryb2 := p2.Y.Bytes()
	//publicWitness.Signature.R.X.Assign(rxb2[:])
	//publicWitness.Signature.R.Y.Assign(ryb2[:])

	// The S part of the signature is a 32 bytes scalar stored in signature[32:64].
	// As decribed earlier, we split is in S1, S2 such that S = 2^128*S1+S2 to prevent
	// overflowing the underlying representation in the circuit.
	//publicWitness.Signature.S1.Assign(signature[32:48])
	//publicWitness.Signature.S2.Assign(signature[48:])

	// generate the proof
	proof, err := groth16.Prove(r1cs, pk, &witness)

	// verify the proof
	err = groth16.Verify(proof, vk, &publicWitness)
	if err != nil {
		fmt.Println(err) // invalid proof
	} else {
		fmt.Println("valid proof") // invalid proof
	}
}