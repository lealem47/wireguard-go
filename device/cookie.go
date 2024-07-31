/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"sync"
	"time"
	"errors"

        wolfSSL "github.com/wolfssl/go-wolfssl"
)

type CookieChecker struct {
	sync.RWMutex
	mac1 struct {
		key [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
	}
	mac2 struct {
		secret        [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
		secretSet     time.Time
		encryptionKey [wolfSSL.AES_256_KEY_SIZE]byte
	}
}

type CookieGenerator struct {
	sync.RWMutex
	mac1 struct {
		key [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
	}
	mac2 struct {
		cookie        [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
		cookieSet     time.Time
		hasLastMAC1   bool
		lastMAC1      [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
		encryptionKey [wolfSSL.AES_256_KEY_SIZE]byte
	}
}

func (st *CookieChecker) Init(pk NoisePublicKey) {
	st.Lock()
	defer st.Unlock()

	// mac1 state

	func() {
                var sha wolfSSL.Wc_Sha256
                wolfSSL.Wc_InitSha256_ex(&sha, nil, wolfSSL.INVALID_DEVID)
                wolfSSL.Wc_Sha256Update(&sha, []byte(WGLabelMAC1), len([]byte(WGLabelMAC1)))
                wolfSSL.Wc_Sha256Update(&sha, pk[:], len(pk[:]))
                wolfSSL.Wc_Sha256Final(&sha, st.mac1.key[:])
                wolfSSL.Wc_Sha256Free(&sha)
        }()

	// mac2 state

	func() {
                var sha wolfSSL.Wc_Sha256
                wolfSSL.Wc_InitSha256_ex(&sha, nil, wolfSSL.INVALID_DEVID)
                wolfSSL.Wc_Sha256Update(&sha, []byte(WGLabelCookie), len([]byte(WGLabelCookie)))
                wolfSSL.Wc_Sha256Update(&sha, pk[:], len(pk[:]))
                wolfSSL.Wc_Sha256Final(&sha, st.mac2.encryptionKey[:])
                wolfSSL.Wc_Sha256Free(&sha)
	}()

	st.mac2.secretSet = time.Time{}
}

func (st *CookieChecker) CheckMAC1(msg []byte) bool {
	st.RLock()
	defer st.RUnlock()

	size := len(msg)
	smac2 := size - wolfSSL.WC_SHA256_DIGEST_SIZE
	smac1 := smac2 - wolfSSL.WC_SHA256_DIGEST_SIZE

	var mac1 [wolfSSL.WC_SHA256_DIGEST_SIZE]byte

        var hmac wolfSSL.Hmac
        wolfSSL.Wc_HmacInit(&hmac, nil, wolfSSL.INVALID_DEVID)
        wolfSSL.Wc_HmacSetKey(&hmac, wolfSSL.WC_SHA256, st.mac1.key[:], len(st.mac1.key[:]))
        wolfSSL.Wc_HmacUpdate(&hmac, msg[:smac1], len(msg[:smac1]))
        wolfSSL.Wc_HmacFinal(&hmac, mac1[:])
        wolfSSL.Wc_HmacFree(&hmac)

        return wolfSSL.ConstantCompare(mac1[:], msg[smac1:smac2], len(mac1)) == 1
}

func (st *CookieChecker) CheckMAC2(msg, src []byte) bool {
	st.RLock()
	defer st.RUnlock()

	if time.Since(st.mac2.secretSet) > CookieRefreshTime {
		return false
	}

	// derive cookie key

	var cookie [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
	func() {
                var hmac wolfSSL.Hmac
                wolfSSL.Wc_HmacInit(&hmac, nil, wolfSSL.INVALID_DEVID)
                wolfSSL.Wc_HmacSetKey(&hmac, wolfSSL.WC_SHA256, st.mac2.secret[:], len(st.mac2.secret[:]))
                wolfSSL.Wc_HmacUpdate(&hmac, src, len(src))
                wolfSSL.Wc_HmacFinal(&hmac, cookie[:])
                wolfSSL.Wc_HmacFree(&hmac)
        }()

	// calculate mac of packet (including mac1)

	smac2 := len(msg) - wolfSSL.WC_SHA256_DIGEST_SIZE

	var mac2 [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
	func() {
                var hmac wolfSSL.Hmac
                wolfSSL.Wc_HmacInit(&hmac, nil, wolfSSL.INVALID_DEVID)
                wolfSSL.Wc_HmacSetKey(&hmac, wolfSSL.WC_SHA256, cookie[:], len(cookie[:]))
                wolfSSL.Wc_HmacUpdate(&hmac, msg[:smac2], len(msg[:smac2]))
                wolfSSL.Wc_HmacFinal(&hmac, mac2[:])
                wolfSSL.Wc_HmacFree(&hmac)
        }()

        return wolfSSL.ConstantCompare(mac2[:], msg[smac2:], len(mac2)) == 1
}

func (st *CookieChecker) CreateReply(
	msg []byte,
	recv uint32,
	src []byte,
) (*MessageCookieReply, error) {
	st.RLock()

	// refresh cookie secret

	if time.Since(st.mac2.secretSet) > CookieRefreshTime {
		st.RUnlock()
		st.Lock()
                var rng wolfSSL.WC_RNG
                wolfSSL.Wc_InitRng(&rng)
                ret := wolfSSL.Wc_RNG_GenerateBlock(&rng, st.mac2.secret[:], len(st.mac2.secret[:]))
                wolfSSL.Wc_FreeRng(&rng)
		if ret < 0 {
			st.Unlock()
			return nil, errors.New("RNG failed")
		}
                st.mac2.secretSet = time.Now()
		st.Unlock()
		st.RLock()
	}

	// derive cookie

	var cookie [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
	func() {
                var hmac wolfSSL.Hmac
                wolfSSL.Wc_HmacInit(&hmac, nil, wolfSSL.INVALID_DEVID)
                wolfSSL.Wc_HmacSetKey(&hmac, wolfSSL.WC_SHA256, st.mac2.secret[:], len(st.mac2.secret[:]))
                wolfSSL.Wc_HmacUpdate(&hmac, src, len(src))
                wolfSSL.Wc_HmacFinal(&hmac, cookie[:])
                wolfSSL.Wc_HmacFree(&hmac)
        }()

	// encrypt cookie

	size := len(msg)

	smac2 := size - wolfSSL.WC_SHA256_DIGEST_SIZE
	smac1 := smac2 - wolfSSL.WC_SHA256_DIGEST_SIZE

	reply := new(MessageCookieReply)
	reply.Type = MessageCookieReplyType
	reply.Receiver = recv

        var rng wolfSSL.WC_RNG
        wolfSSL.Wc_InitRng(&rng)
        ret := wolfSSL.Wc_RNG_GenerateBlock(&rng, reply.Nonce[:], len(reply.Nonce[:]))
        wolfSSL.Wc_FreeRng(&rng)
        if ret < 0 {
		st.RUnlock()
                return nil, errors.New("RNG failed")
        }

        var aes wolfSSL.Aes
        wolfSSL.Wc_AesInit(&aes, nil, wolfSSL.INVALID_DEVID)
        wolfSSL.Wc_AesGcmSetKey(&aes, st.mac2.encryptionKey[:], len(st.mac2.encryptionKey[:]))
        wolfSSL.Wc_AesGcm_Appended_Tag_Encrypt(&aes, reply.Cookie[:], cookie[:], reply.Nonce[:], msg[smac1:smac2])
        wolfSSL.Wc_AesFree(&aes)

	st.RUnlock()

	return reply, nil
}

func (st *CookieGenerator) Init(pk NoisePublicKey) {
	st.Lock()
	defer st.Unlock()

	func() {
                var sha wolfSSL.Wc_Sha256
                wolfSSL.Wc_InitSha256_ex(&sha, nil, wolfSSL.INVALID_DEVID)
                wolfSSL.Wc_Sha256Update(&sha, []byte(WGLabelMAC1), len([]byte(WGLabelMAC1)))
                wolfSSL.Wc_Sha256Update(&sha, pk[:], len(pk[:]))
                wolfSSL.Wc_Sha256Final(&sha, st.mac1.key[:])
                wolfSSL.Wc_Sha256Free(&sha)

        }()

	func() {
                var sha wolfSSL.Wc_Sha256
                wolfSSL.Wc_InitSha256_ex(&sha, nil, wolfSSL.INVALID_DEVID)
                wolfSSL.Wc_Sha256Update(&sha, []byte(WGLabelCookie), len([]byte(WGLabelCookie)))
                wolfSSL.Wc_Sha256Update(&sha, pk[:], len(pk[:]))
                wolfSSL.Wc_Sha256Final(&sha, st.mac2.encryptionKey[:])
                wolfSSL.Wc_Sha256Free(&sha)

        }()

	st.mac2.cookieSet = time.Time{}
}

func (st *CookieGenerator) ConsumeReply(msg *MessageCookieReply) bool {
	st.Lock()
	defer st.Unlock()

	if !st.mac2.hasLastMAC1 {
		return false
	}

	var cookie [wolfSSL.WC_SHA256_DIGEST_SIZE]byte


        var aes wolfSSL.Aes
        wolfSSL.Wc_AesInit(&aes, nil, wolfSSL.INVALID_DEVID)
        wolfSSL.Wc_AesGcmSetKey(&aes, st.mac2.encryptionKey[:], len(st.mac2.encryptionKey[:]))
        ret := wolfSSL.Wc_AesGcm_Appended_Tag_Decrypt(&aes, cookie[:], msg.Cookie[:], msg.Nonce[:], st.mac2.lastMAC1[:])
        wolfSSL.Wc_AesFree(&aes)

	if ret < 0 {
		return false
	}

	st.mac2.cookieSet = time.Now()
	st.mac2.cookie = cookie
	return true
}

func (st *CookieGenerator) AddMacs(msg []byte) {
	size := len(msg)

	smac2 := size - wolfSSL.WC_SHA256_DIGEST_SIZE
	smac1 := smac2 - wolfSSL.WC_SHA256_DIGEST_SIZE

	mac1 := msg[smac1:smac2]
	mac2 := msg[smac2:]

	st.Lock()
	defer st.Unlock()

	// set mac1

	func() {
                var hmac wolfSSL.Hmac
                wolfSSL.Wc_HmacInit(&hmac, nil, wolfSSL.INVALID_DEVID)
                wolfSSL.Wc_HmacSetKey(&hmac, wolfSSL.WC_SHA256, st.mac1.key[:], len(st.mac1.key[:]))
                wolfSSL.Wc_HmacUpdate(&hmac, msg[:smac1], len(msg[:smac1]))
                wolfSSL.Wc_HmacFinal(&hmac, mac1[:])
                wolfSSL.Wc_HmacFree(&hmac)
        }()
	copy(st.mac2.lastMAC1[:], mac1)
	st.mac2.hasLastMAC1 = true

	// set mac2

	if time.Since(st.mac2.cookieSet) > CookieRefreshTime {
		return
	}

	func() {
                var hmac wolfSSL.Hmac
                wolfSSL.Wc_HmacInit(&hmac, nil, wolfSSL.INVALID_DEVID)
                wolfSSL.Wc_HmacSetKey(&hmac, wolfSSL.WC_SHA256, st.mac2.cookie[:], len(st.mac2.cookie[:]))
                wolfSSL.Wc_HmacUpdate(&hmac, msg[:smac2], len(msg[:smac2]))
                wolfSSL.Wc_HmacFinal(&hmac, mac2[:])
                wolfSSL.Wc_HmacFree(&hmac)
        }()
}
