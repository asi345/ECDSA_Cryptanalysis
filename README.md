# ECDSA(Elliptic Curve Digital Signature Algorithm) Cryptanalysis

My solution to 1st module of Information Security Lab Autumn Semester 2022 in ETH Zurich. This a project with 2
parts :

1. Implementing ECC(Elliptic Curve Cryptography) of ECDSA
2. Analysis and Attack on ECDSA

The code is written in Python 3.9.

## ECC of ECDSA
This task is focused on implementing a framework for Elliptic-Curve Cryptography (ECC) from the ground-up, and using the same to build an implementation of the Elliptic Curve Digital Signature Algorithm (ECDSA). Only standard libraries are used for this task.

In the task, I implemented the Elliptic Curve Cryptography fundamentals and objects to be used later
for constructing ECDSA. Point, Point at Infinity, Addition on Points, Scalar Multiplication on
    Points are defined in this section.

Then, I implemented a ECDSA algorithm on the elliptic curve defined by earlier task. This part
handles Key Generation, Sign with generating nonces and Verify functions.

The implementation can be found in **ECC_ECDSA/module_1_ECC_ECDSA_Skel.py**. The detailed task
description can be found in **module_1_ECC_ECDSA.pdf**.

## Cryptanalysis of ECDSA
This lab is focused on implementing cryptanalysis of ECDSA based on nonce leakages. In other words, I implemented attack algorithms that recover the secret ECDSA signing key based on either complete or partial information about the nonce(s) used in the ECDSA signing algorithm. I looked at three flavors of cryptanalytic attacks, namely known-nonce attacks, repeated-nonce attacks and partially-known-nonce attacks.

The third one is significantly more involved and requires the use of lattice-based techniques. I implemented two variants of the third attack, one where the most significant bits of the nonce are leaked, the other where the least significant bits of the nonce are leaked. Finally, I also implemented the partial-known-nonce attacks on Schnorr signatures, a similar signature scheme to ECDSA.

**fpyll** library is used for lattice-based analysis and computations. I constructed the lattices
and ***LLL*** reductions are performed on them. Then, CVP(Closest Vector Problem) and SVP(Shortest
Vector Problem) are solved in these lattices to get the secret key based on the partially obtained
nonces.

The implementation can be found in **ECDSA_Cryptanalysis/module_1_ECDSA_Cryptanalysis_Skel.py**. The
detailed task description can be found in **module_1_ECDSA_Cryptanalysis.pdf**.
