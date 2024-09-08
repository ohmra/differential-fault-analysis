# differential-fault-analysis
Simple DFA on AES-128

This attack is based on a faulty AES-128 ciphered text.
The attack considered in this code is based on the following assumptions:
- We have access to a plaintext and the corresponding faulty and non-faulty results.
- The faulty execution has undergone a fault after the mixColumns of the 7th round (round with index 6 in the code) and before the mixColumns of the 8th round (round with index 7 in the code).
- The fault affects a single byte, in an arbitrary manner.

The attacker knows the plain text, the ciphered text, and a faulty ciphered text and want to retrieve the key used on the AES algorithm.

The general aim of the attack is to reduce the possible values for the key bytes before performing an exhaustive enumeration of the complete possible keys, by checking if the encrypted plaintext matches the non-faulty ciphertext.

In order to reduce the possible values for the key bytes, we rely on a differential analysis of the faulty and non-faulty results. This leads to the following 16 equations:

```
2 * δ = SBox−1[x0 ⊕ k0] ⊕ Sbox−1[x'0 ⊕ k0]
δ = SBox−1[x13 ⊕ k13] ⊕ Sbox−1[x'13 ⊕ k13]
δ = SBox−1[x10 ⊕ k10] ⊕ Sbox−1[x'10 ⊕ k10]
3 * δ = SBox−1[x7 ⊕ k7] ⊕ Sbox−1[x'7 ⊕ k7]

δ = SBox−1[x4 ⊕ k4] ⊕ Sbox−1[x'4 ⊕ k4]
δ = SBox−1[x1 ⊕ k1] ⊕ Sbox−1[x'1 ⊕ k1]
3 * δ = SBox−1[x14 ⊕ k10] ⊕ Sbox−1[x'14 ⊕ k14]
2 * δ = SBox−1[x11 ⊕ k11] ⊕ Sbox−1[x'11 ⊕ k11]

δ = SBox−1[x8 ⊕ k8] ⊕ Sbox−1[x'8 ⊕ k8]
3 * δ = SBox−1[x5 ⊕ k5] ⊕ Sbox−1[x'5 ⊕ k5]
2 * δ = SBox−1[x2 ⊕ k2] ⊕ Sbox−1[x'2 ⊕ k2]
δ = SBox−1[x15 ⊕ k15] ⊕ Sbox−1[x'15 ⊕ k15]

δ = SBox−1[x12 ⊕ k12] ⊕ Sbox−1[x'12 ⊕ k12]
δ = SBox−1[x9 ⊕ k9] ⊕ Sbox−1[x'9 ⊕ k9]
3 * δ = SBox−1[x6 ⊕ k6] ⊕ Sbox−1[x'6 ⊕ k6]
2 * δ = SBox−1[x3 ⊕ k3] ⊕ Sbox−1[x'3 ⊕ k3]
```
In which δ, k1..k15 are unknowns, and the xi (bytes of the non-faulty ciphertext) and x'i (bytes of the faulty ciphertext) are known. It should be noted that the multiplication used here is that of the finite field, the same one used in mixColumns.

# Files 
The ```dfa.c``` perfoms the differential fault analysis and the ```key_test.c``` to do AES-128 encryption and check if the provided key return the correct cipher text

# In this example :
Plaintext = 0x6cdf1e5651a1796b9b6b9ace431db598
Ciphertext = 0xb344534e6711d484e265ca71b0c39be9
Faulty Ciphertext = 0xd52c3494ae4c1bd9a7a7ce5c50ac3ecc
KEY = { 0xd0, 0x31, 0x93, 0x17, 0xc7, 0x78, 0xa7, 0xf1, 0x80, 0xee, 0x31, 0x38, 0x95, 0x60, 0xc8, 0x60 }

The search goes on for ~20 minutes
