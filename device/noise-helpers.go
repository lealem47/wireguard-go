/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
        wolfSSL "github.com/wolfssl/go-wolfssl"
	"errors"
    )

/* KDF related functions.
 * HMAC-based Key Derivation Function (HKDF)
 * https://tools.ietf.org/html/rfc5869
 */

func HMAC1(sum *[wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte, key, in0 []byte) {
        wolfSSL.Wc_Blake2s_HMAC(sum[:], in0, key, wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE)
}

func HMAC2(sum *[wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte, key, in0, in1 []byte) {
        in := append(in0, in1...)
        wolfSSL.Wc_Blake2s_HMAC(sum[:], in, key, wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE)
}

func KDF1(t0 *[wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte, key, input []byte) {
	HMAC1(t0, key, input)
	HMAC1(t0, t0[:], []byte{0x1})
}

func KDF2(t0, t1 *[wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte, key, input []byte) {
	var prk [wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	setZero(prk[:])
}

func KDF3(t0, t1, t2 *[wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte, key, input []byte) {
	var prk [wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	HMAC2(t2, prk[:], t1[:], []byte{0x3})
	setZero(prk[:])
}

func isZero(val []byte) bool {
        acc := byte(0)
        for _, b := range val {
            acc |= b
        }
        return acc == 0
}

/* This function is not used as pervasively as it should because this is mostly impossible in Go at the moment */
func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}


func newPrivateKey() (sk NoisePrivateKey, err error) {
        var rng wolfSSL.WC_RNG

        wolfSSL.Wc_InitRng(&rng)

        wolfSSL.Wc_curve25519_make_priv(&rng, sk[:])

        wolfSSL.Wc_FreeRng(&rng)

        return
}

func (sk *NoisePrivateKey) publicKey() (pk NoisePublicKey) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)

        wolfSSL.Wc_curve25519_make_pub(apk[:], ask[:])

        return
}

var errInvalidPublicKey = errors.New("invalid public key")

func (sk *NoisePrivateKey) sharedSecret(pk NoisePublicKey) (ss [NoisePublicKeySize]byte, err error) {
        var privKey wolfSSL.Curve25519_key
        var pubKey wolfSSL.Curve25519_key

        apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)

        wolfSSL.Wc_curve25519_init(&privKey)
        wolfSSL.Wc_curve25519_init(&pubKey)


        wolfSSL.Wc_curve25519_import_private(ask[:], &privKey)
        wolfSSL.Wc_curve25519_import_public(apk[:], &pubKey)
        
        wolfSSL.Wc_curve25519_shared_secret(&privKey, &pubKey, ss[:])

        wolfSSL.Wc_curve25519_free(&privKey)
        wolfSSL.Wc_curve25519_free(&pubKey)

        return ss, nil
}

