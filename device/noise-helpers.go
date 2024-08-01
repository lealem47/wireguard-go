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

func HMAC1(sum []byte, key, in0 []byte) {
        var hmac wolfSSL.Hmac
        wolfSSL.Wc_HmacInit(&hmac, nil, wolfSSL.INVALID_DEVID)
        wolfSSL.Wc_HmacSetKey(&hmac, wolfSSL.WC_SHA256, key, len(key[:]))
        wolfSSL.Wc_HmacUpdate(&hmac, in0, len(in0[:]))
        wolfSSL.Wc_HmacFinal(&hmac, sum)
        wolfSSL.Wc_HmacFree(&hmac)
}

func HMAC2(sum []byte, key, in0, in1 []byte) {
        var hmac wolfSSL.Hmac
        wolfSSL.Wc_HmacInit(&hmac, nil, wolfSSL.INVALID_DEVID)
        wolfSSL.Wc_HmacSetKey(&hmac, wolfSSL.WC_SHA256, key, len(key[:]))
        wolfSSL.Wc_HmacUpdate(&hmac, in0, len(in0[:]))
        wolfSSL.Wc_HmacUpdate(&hmac, in1, len(in1[:]))
        wolfSSL.Wc_HmacFinal(&hmac, sum)
        wolfSSL.Wc_HmacFree(&hmac)
}

func KDF1(t0 []byte, key, input []byte) {
	HMAC1(t0, key, input)
	HMAC1(t0, t0[:], []byte{0x1})
}

func KDF2(t0, t1 []byte, key, input []byte) {
	var prk [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
        HMAC1(prk[:], key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	setZero(prk[:])
}

func KDF3(t0, t1, t2 []byte, key, input []byte) {
	var prk [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
        HMAC1(prk[:], key, input)
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
        var key wolfSSL.Ecc_key

        if ret := wolfSSL.Wc_ecc_init(&key); ret != 0 {
            return sk, errors.New("Failed to initialize ECC key")
        }

        wolfSSL.Wc_InitRng(&rng)

        keySize := NoisePrivateKeySize
        if ret := wolfSSL.Wc_ecc_make_key(&rng, keySize, &key); ret != 0 {
            wolfSSL.Wc_FreeRng(&rng)
            wolfSSL.Wc_ecc_free(&key)
            return sk, errors.New("Failed to make ECC key")
        }

        skLen := len(sk[:])
        if ret := wolfSSL.Wc_ecc_export_private_only(&key, sk[:], &skLen); ret != 0 {
            wolfSSL.Wc_FreeRng(&rng)
            wolfSSL.Wc_ecc_free(&key)
            return sk, errors.New("Failed to export private ECC key")
        }

        return sk, nil
}

func (sk *NoisePrivateKey) publicKey() (pk NoisePublicKey) {
        var key wolfSSL.Ecc_key

        apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)

        askSz := len(ask[:])
        apkSz := len(apk[:])

        wolfSSL.Wc_ecc_init(&key)

        wolfSSL.Wc_ecc_import_private_key_ex(ask[:], askSz, nil, 0, &key, wolfSSL.ECC_SECP256R1)
        wolfSSL.Wc_ecc_make_pub(&key, nil)

        wolfSSL.PRIVATE_KEY_UNLOCK()
        wolfSSL.Wc_ecc_export_x963_ex(&key, apk[:], &apkSz, 0)
        wolfSSL.PRIVATE_KEY_LOCK()

        wolfSSL.Wc_ecc_free(&key)

        return
}

var errInvalidPublicKey = errors.New("invalid public key")

func (sk *NoisePrivateKey) sharedSecret(pk NoisePublicKey) (ss [NoisePrivateKeySize]byte, err error) {
        var privKey wolfSSL.Ecc_key
        var pubKey  wolfSSL.Ecc_key
        var rng wolfSSL.WC_RNG

        apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)

        wolfSSL.Wc_ecc_init(&privKey)
        wolfSSL.Wc_ecc_init(&pubKey)

        if ret := wolfSSL.Wc_ecc_import_private_key_ex(ask[:], len(ask[:]), nil, 0, &privKey, wolfSSL.ECC_SECP256R1); ret != 0 {
            wolfSSL.Wc_ecc_free(&privKey)
            wolfSSL.Wc_ecc_free(&pubKey)
            return ss, errors.New("Failed import private ECC key")
        }

        if ret := wolfSSL.Wc_ecc_import_x963_ex(apk[:], len(apk[:]), &pubKey, wolfSSL.ECC_SECP256R1); ret != 0 {
            wolfSSL.Wc_ecc_free(&privKey)
            wolfSSL.Wc_ecc_free(&pubKey)
            return ss, errors.New("Failed import public ECC key")
        }
       
        ssSz := len(ss[:])

        wolfSSL.Wc_InitRng(&rng)

        wolfSSL.PRIVATE_KEY_UNLOCK()
        if ret := wolfSSL.Wc_ecc_shared_secret(&privKey, &pubKey, ss[:], &ssSz); ret != 0 {
            wolfSSL.Wc_ecc_free(&privKey)
            wolfSSL.Wc_ecc_free(&pubKey)
            wolfSSL.Wc_FreeRng(&rng)
            return ss, errors.New("Failed create ECC shared secret")
        }
        wolfSSL.PRIVATE_KEY_LOCK()

        wolfSSL.Wc_FreeRng(&rng)
        wolfSSL.Wc_ecc_free(&privKey)
        wolfSSL.Wc_ecc_free(&pubKey)

        return ss, nil
}

