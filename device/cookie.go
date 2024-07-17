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
		key [wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte
	}
	mac2 struct {
		secret        [wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte
		secretSet     time.Time
		encryptionKey [wolfSSL.AES_256_KEY_SIZE]byte
	}
}

type CookieGenerator struct {
	sync.RWMutex
	mac1 struct {
		key [wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte
	}
	mac2 struct {
		cookie        [wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE]byte
		cookieSet     time.Time
		hasLastMAC1   bool
		lastMAC1      [wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE]byte
		encryptionKey [wolfSSL.AES_256_KEY_SIZE]byte
	}
}

func (st *CookieChecker) Init(pk NoisePublicKey) {
	st.Lock()
	defer st.Unlock()

	// mac1 state

	func() {
                var blake2s wolfSSL.Blake2s
                wolfSSL.Wc_InitBlake2s(&blake2s, wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE)
                wolfSSL.Wc_Blake2sUpdate(&blake2s, []byte(WGLabelMAC1), len([]byte(WGLabelMAC1)))
                wolfSSL.Wc_Blake2sUpdate(&blake2s, pk[:], len(pk[:]))
                wolfSSL.Wc_Blake2sFinal(&blake2s, st.mac1.key[:], 0)
        }()

	// mac2 state

	func() {
                var blake2s wolfSSL.Blake2s
                wolfSSL.Wc_InitBlake2s(&blake2s, wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE)
                wolfSSL.Wc_Blake2sUpdate(&blake2s, []byte(WGLabelCookie), len([]byte(WGLabelCookie)))
                wolfSSL.Wc_Blake2sUpdate(&blake2s, pk[:], len(pk[:]))
                wolfSSL.Wc_Blake2sFinal(&blake2s, st.mac2.encryptionKey[:], 0)
	}()

	st.mac2.secretSet = time.Time{}
}

func (st *CookieChecker) CheckMAC1(msg []byte) bool {
	st.RLock()
	defer st.RUnlock()

	size := len(msg)
	smac2 := size - wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE
	smac1 := smac2 - wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE

	var mac1 [wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE]byte

                
        var blake2s wolfSSL.Blake2s
        wolfSSL.Wc_InitBlake2s_WithKey(&blake2s, wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE, st.mac1.key[:])
        wolfSSL.Wc_Blake2sUpdate(&blake2s, msg[:smac1], len(msg[:smac1]))
        wolfSSL.Wc_Blake2sFinal(&blake2s, mac1[:], 0)

        return wolfSSL.ConstantCompare(mac1[:], msg[smac1:smac2], len(mac1)) == 1
}

func (st *CookieChecker) CheckMAC2(msg, src []byte) bool {
	st.RLock()
	defer st.RUnlock()

	if time.Since(st.mac2.secretSet) > CookieRefreshTime {
		return false
	}

	// derive cookie key

	var cookie [wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE]byte
	func() {
                var blake2s wolfSSL.Blake2s
                wolfSSL.Wc_InitBlake2s_WithKey(&blake2s, wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE, st.mac2.secret[:])
                wolfSSL.Wc_Blake2sUpdate(&blake2s, src, len(src))
                wolfSSL.Wc_Blake2sFinal(&blake2s, cookie[:], 0)
	}()

	// calculate mac of packet (including mac1)

	smac2 := len(msg) - wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE

	var mac2 [wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE]byte
	func() {
                var blake2s wolfSSL.Blake2s
                wolfSSL.Wc_InitBlake2s_WithKey(&blake2s, wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE, cookie[:])
                wolfSSL.Wc_Blake2sUpdate(&blake2s, msg[:smac2], len(msg[:smac2]))
                wolfSSL.Wc_Blake2sFinal(&blake2s, mac2[:], 0)
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

	var cookie [wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE]byte
	func() {
                var blake2s wolfSSL.Blake2s
                wolfSSL.Wc_InitBlake2s_WithKey(&blake2s, wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE, st.mac2.secret[:])
                wolfSSL.Wc_Blake2sUpdate(&blake2s, src, len(src))
                wolfSSL.Wc_Blake2sFinal(&blake2s, cookie[:], 0)
        }()

	// encrypt cookie

	size := len(msg)

	smac2 := size - wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE
	smac1 := smac2 - wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE

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

        wolfSSL.Wc_XChaCha20Poly1305_Encrypt(reply.Cookie[:], cookie[:], msg[smac1:smac2], reply.Nonce[:], st.mac2.encryptionKey[:])

	st.RUnlock()

	return reply, nil
}

func (st *CookieGenerator) Init(pk NoisePublicKey) {
	st.Lock()
	defer st.Unlock()

	func() {
                var blake2s wolfSSL.Blake2s
                wolfSSL.Wc_InitBlake2s(&blake2s, wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE)
                wolfSSL.Wc_Blake2sUpdate(&blake2s, []byte(WGLabelMAC1), len([]byte(WGLabelMAC1)))
                wolfSSL.Wc_Blake2sUpdate(&blake2s, pk[:], len(pk[:]))
                wolfSSL.Wc_Blake2sFinal(&blake2s, st.mac1.key[:], 0)

        }()

	func() {
                var blake2s wolfSSL.Blake2s
                wolfSSL.Wc_InitBlake2s(&blake2s, wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE)
                wolfSSL.Wc_Blake2sUpdate(&blake2s, []byte(WGLabelCookie), len([]byte(WGLabelCookie)))
                wolfSSL.Wc_Blake2sUpdate(&blake2s, pk[:], len(pk[:]))
                wolfSSL.Wc_Blake2sFinal(&blake2s, st.mac2.encryptionKey[:], 0)

        }()

	st.mac2.cookieSet = time.Time{}
}

func (st *CookieGenerator) ConsumeReply(msg *MessageCookieReply) bool {
	st.Lock()
	defer st.Unlock()

	if !st.mac2.hasLastMAC1 {
		return false
	}

	var cookie [wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE]byte

        ret := wolfSSL.Wc_XChaCha20Poly1305_Decrypt(cookie[:], msg.Cookie[:], st.mac2.lastMAC1[:], msg.Nonce[:], st.mac2.encryptionKey[:])
	if ret < 0 {
		return false
	}

	st.mac2.cookieSet = time.Now()
	st.mac2.cookie = cookie
	return true
}

func (st *CookieGenerator) AddMacs(msg []byte) {
	size := len(msg)

	smac2 := size - wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE
	smac1 := smac2 - wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE

	mac1 := msg[smac1:smac2]
	mac2 := msg[smac2:]

	st.Lock()
	defer st.Unlock()

	// set mac1

	func() {
                var blake2s wolfSSL.Blake2s
                wolfSSL.Wc_InitBlake2s_WithKey(&blake2s, wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE, st.mac1.key[:])
                wolfSSL.Wc_Blake2sUpdate(&blake2s, msg[:smac1], len(msg[:smac1]))
                wolfSSL.Wc_Blake2sFinal(&blake2s, mac1[:], 0)
        }()
	copy(st.mac2.lastMAC1[:], mac1)
	st.mac2.hasLastMAC1 = true

	// set mac2

	if time.Since(st.mac2.cookieSet) > CookieRefreshTime {
		return
	}

	func() {
                var blake2s wolfSSL.Blake2s
                wolfSSL.Wc_InitBlake2s_WithKey(&blake2s, wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE, st.mac2.cookie[:])
                wolfSSL.Wc_Blake2sUpdate(&blake2s, msg[:smac2], len(msg[:smac2]))
                wolfSSL.Wc_Blake2sFinal(&blake2s, mac2[:], 0)
        }()
}
