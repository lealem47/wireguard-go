/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"
	"fmt"
	"sync"
	"time"
	"bytes"

        wolfSSL "github.com/wolfssl/go-wolfssl"

	"golang.zx2c4.com/wireguard/tai64n"
)

type handshakeState int

const (
	handshakeZeroed = handshakeState(iota)
	handshakeInitiationCreated
	handshakeInitiationConsumed
	handshakeResponseCreated
	handshakeResponseConsumed
)

func (hs handshakeState) String() string {
	switch hs {
	case handshakeZeroed:
		return "handshakeZeroed"
	case handshakeInitiationCreated:
		return "handshakeInitiationCreated"
	case handshakeInitiationConsumed:
		return "handshakeInitiationConsumed"
	case handshakeResponseCreated:
		return "handshakeResponseCreated"
	case handshakeResponseConsumed:
		return "handshakeResponseConsumed"
	default:
		return fmt.Sprintf("Handshake(UNKNOWN:%d)", int(hs))
	}
}

const (
	NoiseConstruction = "Noise_IKpsk2_ECC_256_AesGcm_SHA"
	WGIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	WGLabelMAC1       = "mac1----"
	WGLabelCookie     = "cookie--"
)

const (
	MessageInitiationType  = 1
	MessageResponseType    = 2
	MessageCookieReplyType = 3
	MessageTransportType   = 4
)

const (
	MessageInitiationSize      = 214                                           // size of handshake initiation message
	MessageResponseSize        = 125                                            // size of response message
	MessageCookieReplySize     = 64                                            // size of cookie reply message
	MessageTransportHeaderSize = 16                                            // size of data preceding content in transport message
	MessageTransportSize       = MessageTransportHeaderSize + wolfSSL.AES_BLOCK_SIZE   // size of empty transport
	MessageKeepaliveSize       = MessageTransportSize                          // size of keepalive
	MessageHandshakeSize       = MessageInitiationSize                         // size of largest handshake related message
)

const (
	MessageTransportOffsetReceiver = 4
	MessageTransportOffsetCounter  = 8
	MessageTransportOffsetContent  = 16
)

/* Type is an 8-bit field, followed by 3 nul bytes,
 * by marshalling the messages in little-endian byteorder
 * we can treat these as a 32-bit unsigned int (for now)
 *
 */

type MessageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral NoisePublicKey
	Static    [NoisePublicKeySize + wolfSSL.AES_BLOCK_SIZE]byte
	Timestamp [tai64n.TimestampSize + wolfSSL.AES_BLOCK_SIZE]byte
	MAC1      [wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE]byte
	MAC2      [wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE]byte
}

type MessageResponse struct {
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral NoisePublicKey
	Empty     [wolfSSL.AES_BLOCK_SIZE]byte
	MAC1      [wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE]byte
	MAC2      [wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE]byte
}

type MessageTransport struct {
	Type     uint32
	Receiver uint32
	Counter  uint64
	Content  []byte
}

type MessageCookieReply struct {
	Type     uint32
	Receiver uint32
	Nonce    [wolfSSL.XCHACHA20_POLY1305_AEAD_NONCE_SIZE]byte
	Cookie   [wolfSSL.WC_BLAKE2S_128_DIGEST_SIZE + wolfSSL.AES_BLOCK_SIZE]byte
}

type Handshake struct {
	state                     handshakeState
	mutex                     sync.RWMutex
	hash                      [wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte       // hash value
	chainKey                  [wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte       // chain key
	presharedKey              NoisePresharedKey        // psk
	localEphemeral            NoisePrivateKey          // ephemeral secret key
	localIndex                uint32                   // used to clear hash-table
	remoteIndex               uint32                   // index for sending
	remoteStatic              NoisePublicKey           // long term key
	remoteEphemeral           NoisePublicKey           // ephemeral public key
	precomputedStaticStatic   [NoisePrivateKeySize]byte // precomputed shared secret
	lastTimestamp             tai64n.Timestamp
	lastInitiationConsumption time.Time
	lastSentHandshake         time.Time
}

var (
	InitialChainKey [wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte
	InitialHash     [wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte
	ZeroNonce       [wolfSSL.AES_IV_SIZE]byte
)

func mixKey(dst, c, data []byte) {
    KDF1(dst, c, data)
}

func mixHash(dst, h , data []byte) {
        var blake2s wolfSSL.Blake2s
        wolfSSL.Wc_InitBlake2s(&blake2s, wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE)
        wolfSSL.Wc_Blake2sUpdate(&blake2s, h[:], len(h[:]))
        wolfSSL.Wc_Blake2sUpdate(&blake2s, data, len(data))
        wolfSSL.Wc_Blake2sFinal(&blake2s, dst[:], len(dst[:]))
}

func (h *Handshake) Clear() {
	setZero(h.localEphemeral[:])
	setZero(h.remoteEphemeral[:])
	setZero(h.chainKey[:])
	setZero(h.hash[:])
	h.localIndex = 0
	h.state = handshakeZeroed
}

func (h *Handshake) mixHash(data []byte) {
    mixHash(h.hash[:], h.hash[:], data)
}

func (h *Handshake) mixKey(data []byte) {
    mixKey(h.chainKey[:], h.chainKey[:], data)
}

/* Do basic precomputations
 */
func init() {
        var blake2s wolfSSL.Blake2s

        wolfSSL.Wc_InitBlake2s(&blake2s, wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE)
        wolfSSL.Wc_Blake2sUpdate(&blake2s, []byte(NoiseConstruction), len([]byte(NoiseConstruction)))
        wolfSSL.Wc_Blake2sFinal(&blake2s, InitialChainKey[:], len(InitialChainKey[:]))

        mixHash(InitialHash[:], InitialChainKey[:], []byte(WGIdentifier))
}

func (device *Device) CreateMessageInitiation(peer *Peer) (*MessageInitiation, error) {
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// create ephemeral key
	var err error
	handshake.hash = InitialHash
	handshake.chainKey = InitialChainKey
	handshake.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}

	handshake.mixHash(handshake.remoteStatic[:])

	msg := MessageInitiation{
		Type:      MessageInitiationType,
		Ephemeral: handshake.localEphemeral.publicKey(),
	}

	handshake.mixKey(msg.Ephemeral[:])
	handshake.mixHash(msg.Ephemeral[:])

	// encrypt static key
	ss, err := handshake.localEphemeral.sharedSecret(handshake.remoteStatic)
	if err != nil {
		return nil, err
	}
	var key [wolfSSL.AES_256_KEY_SIZE]byte
	KDF2(
                handshake.chainKey[:],
                key[:],
		handshake.chainKey[:],
		ss[:],
	)

        var aes wolfSSL.Aes
        wolfSSL.Wc_AesInit(&aes, nil, wolfSSL.INVALID_DEVID)
        wolfSSL.Wc_AesGcmSetKey(&aes, key[:], len(key[:]))
        wolfSSL.Wc_AesGcm_Appended_Tag_Encrypt(&aes, msg.Static[:], device.staticIdentity.publicKey[:], ZeroNonce[:], handshake.hash[:])
        wolfSSL.Wc_AesFree(&aes)
	handshake.mixHash(msg.Static[:])

	// encrypt timestamp
	if isZero(handshake.precomputedStaticStatic[:]) {
		return nil, errInvalidPublicKey
	}
	KDF2(
                handshake.chainKey[:],
                key[:],
		handshake.chainKey[:],
		handshake.precomputedStaticStatic[:],
	)
	timestamp := tai64n.Now()
        wolfSSL.Wc_AesInit(&aes, nil, wolfSSL.INVALID_DEVID)
        wolfSSL.Wc_AesGcmSetKey(&aes, key[:], len(key[:]))
        wolfSSL.Wc_AesGcm_Appended_Tag_Encrypt(&aes, msg.Timestamp[:], timestamp[:], ZeroNonce[:], handshake.hash[:])
        wolfSSL.Wc_AesFree(&aes)

        // assign index
	device.indexTable.Delete(handshake.localIndex)
	msg.Sender, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}
	handshake.localIndex = msg.Sender

	handshake.mixHash(msg.Timestamp[:])
	handshake.state = handshakeInitiationCreated
	return &msg, nil
}

func (device *Device) ConsumeMessageInitiation(msg *MessageInitiation) *Peer {
	var (
		hash     [wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte
		chainKey [wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte
	)

	if msg.Type != MessageInitiationType {
		return nil
	}

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

        mixHash(hash[:], InitialHash[:], device.staticIdentity.publicKey[:])
        mixHash(hash[:], hash[:], msg.Ephemeral[:])
        mixKey(chainKey[:], InitialChainKey[:], msg.Ephemeral[:])

	// decrypt static key
	var peerPK NoisePublicKey
	var key [wolfSSL.AES_256_KEY_SIZE]byte
	ss, err := device.staticIdentity.privateKey.sharedSecret(msg.Ephemeral)
	if err != nil {
		return nil
	}
        KDF2(chainKey[:], key[:], chainKey[:], ss[:])
        var aes wolfSSL.Aes
        wolfSSL.Wc_AesInit(&aes, nil, wolfSSL.INVALID_DEVID)
        wolfSSL.Wc_AesGcmSetKey(&aes, key[:], len(key[:]))
        wolfSSL.Wc_AesGcm_Appended_Tag_Decrypt(&aes, peerPK[:], msg.Static[:], ZeroNonce[:], hash[:])
        wolfSSL.Wc_AesFree(&aes)
        mixHash(hash[:], hash[:], msg.Static[:])

	// lookup peer

	peer := device.LookupPeer(peerPK)
	if peer == nil || !peer.isRunning.Load() {
		return nil
	}

	handshake := &peer.handshake

	// verify identity

	var timestamp tai64n.Timestamp

	handshake.mutex.RLock()

	if isZero(handshake.precomputedStaticStatic[:]) {
		handshake.mutex.RUnlock()
		return nil
	}
	KDF2(
                chainKey[:],
                key[:],
		chainKey[:],
		handshake.precomputedStaticStatic[:],
	)
        wolfSSL.Wc_AesInit(&aes, nil, wolfSSL.INVALID_DEVID)
        wolfSSL.Wc_AesGcmSetKey(&aes, key[:], len(key[:]))
        ret := wolfSSL.Wc_AesGcm_Appended_Tag_Decrypt(&aes, timestamp[:], msg.Timestamp[:], ZeroNonce[:], hash[:])
        wolfSSL.Wc_AesFree(&aes)
        if ret < 0 {
		handshake.mutex.RUnlock()
		return nil
	}
        mixHash(hash[:], hash[:], msg.Timestamp[:])

	// protect against replay & flood

	replay := !timestamp.After(handshake.lastTimestamp)
	flood := time.Since(handshake.lastInitiationConsumption) <= HandshakeInitationRate
	handshake.mutex.RUnlock()
	if replay {
		device.log.Verbosef("%v - ConsumeMessageInitiation: handshake replay @ %v", peer, timestamp)
		return nil
	}
	if flood {
		device.log.Verbosef("%v - ConsumeMessageInitiation: handshake flood", peer)
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.remoteEphemeral = msg.Ephemeral
	if timestamp.After(handshake.lastTimestamp) {
		handshake.lastTimestamp = timestamp
	}
	now := time.Now()
	if now.After(handshake.lastInitiationConsumption) {
		handshake.lastInitiationConsumption = now
	}
	handshake.state = handshakeInitiationConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return peer
}

func (device *Device) CreateMessageResponse(peer *Peer) (*MessageResponse, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if handshake.state != handshakeInitiationConsumed {
		return nil, errors.New("handshake initiation must be consumed first")
	}

	// assign index

	var err error
	device.indexTable.Delete(handshake.localIndex)
	handshake.localIndex, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}

	var msg MessageResponse
	msg.Type = MessageResponseType
	msg.Sender = handshake.localIndex
	msg.Receiver = handshake.remoteIndex

	// create ephemeral key

	handshake.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}
	msg.Ephemeral = handshake.localEphemeral.publicKey()
	handshake.mixHash(msg.Ephemeral[:])
	handshake.mixKey(msg.Ephemeral[:])

	ss, err := handshake.localEphemeral.sharedSecret(handshake.remoteEphemeral)
	if err != nil {
		return nil, err
	}
	handshake.mixKey(ss[:])
	ss, err = handshake.localEphemeral.sharedSecret(handshake.remoteStatic)
	if err != nil {
		return nil, err
	}
	handshake.mixKey(ss[:])

	// add preshared key

	var tau [wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte
	var key [wolfSSL.AES_256_KEY_SIZE]byte

	KDF3(
                handshake.chainKey[:],
                tau[:],
                key[:],
		handshake.chainKey[:],
		handshake.presharedKey[:],
	)

	handshake.mixHash(tau[:])

        var testOut [NoisePublicKeySize + wolfSSL.AES_BLOCK_SIZE]byte
        var testIn [NoisePublicKeySize]byte
        var aes wolfSSL.Aes
        wolfSSL.Wc_AesInit(&aes, nil, wolfSSL.INVALID_DEVID)
        wolfSSL.Wc_AesGcmSetKey(&aes, key[:], len(key[:]))
        wolfSSL.Wc_AesGcmEncrypt(&aes, testOut[:], testIn[:], ZeroNonce[:], msg.Empty[:], handshake.hash[:])
        wolfSSL.Wc_AesFree(&aes)
        setZero(testOut[:])

	handshake.mixHash(msg.Empty[:])

	handshake.state = handshakeResponseCreated

	return &msg, nil
}

func (device *Device) ConsumeMessageResponse(msg *MessageResponse) *Peer {
	if msg.Type != MessageResponseType {
		return nil
	}

	// lookup handshake by receiver

	lookup := device.indexTable.Lookup(msg.Receiver)
	handshake := lookup.handshake
	if handshake == nil {
		return nil
	}

	var (
		hash     [wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte
		chainKey [wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte
	)

	ok := func() bool {
		// lock handshake state

		handshake.mutex.RLock()
		defer handshake.mutex.RUnlock()

		if handshake.state != handshakeInitiationCreated {
			return false
		}

		// lock private key for reading

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		// finish 3-way DH

                mixHash(hash[:], handshake.hash[:], msg.Ephemeral[:])
                mixKey(chainKey[:], handshake.chainKey[:], msg.Ephemeral[:])

		ss, err := handshake.localEphemeral.sharedSecret(msg.Ephemeral)
		if err != nil {
			return false
		}
                mixKey(chainKey[:], chainKey[:], ss[:])
		setZero(ss[:])

		ss, err = device.staticIdentity.privateKey.sharedSecret(msg.Ephemeral)
		if err != nil {
			return false
		}
                mixKey(chainKey[:], chainKey[:], ss[:])
		setZero(ss[:])

		// add preshared key (psk)

		var tau [wolfSSL.WC_BLAKE2S_256_DIGEST_SIZE]byte
		var key [wolfSSL.AES_256_KEY_SIZE]byte
		KDF3(
                        chainKey[:],
                        tau[:],
                        key[:],
			chainKey[:],
			handshake.presharedKey[:],
		)
                mixHash(hash[:], hash[:], tau[:])

		// authenticate transcript

                var testOut [NoisePublicKeySize + wolfSSL.AES_BLOCK_SIZE]byte
                var testIn [NoisePublicKeySize]byte
                var authTag [wolfSSL.AES_BLOCK_SIZE]byte
                var aes wolfSSL.Aes
                wolfSSL.Wc_AesInit(&aes, nil, wolfSSL.INVALID_DEVID)
                wolfSSL.Wc_AesGcmSetKey(&aes, key[:], len(key[:]))
                wolfSSL.Wc_AesGcmEncrypt(&aes, testOut[:], testIn[:], ZeroNonce[:], authTag[:], hash[:])
                wolfSSL.Wc_AesFree(&aes)
                setZero(testOut[:])

                if !bytes.Equal(authTag[:], msg.Empty[:]) {
                    return false
		}
                mixHash(hash[:], hash[:], msg.Empty[:])
		return true
	}()

	if !ok {
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.state = handshakeResponseConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return lookup.peer
}

/* Derives a new keypair from the current handshake state
 *
 */
func (peer *Peer) BeginSymmetricSession() error {
	device := peer.device
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// derive keys

	var isInitiator bool
	var sendKey [wolfSSL.AES_256_KEY_SIZE]byte
	var recvKey [wolfSSL.AES_256_KEY_SIZE]byte

	if handshake.state == handshakeResponseConsumed {
		KDF2(
                        sendKey[:],
                        recvKey[:],
			handshake.chainKey[:],
			nil,
		)
		isInitiator = true
	} else if handshake.state == handshakeResponseCreated {
		KDF2(
                        recvKey[:],
                        sendKey[:],
			handshake.chainKey[:],
			nil,
		)
		isInitiator = false
	} else {
		return fmt.Errorf("invalid state for keypair derivation: %v", handshake.state)
	}

	// zero handshake

	setZero(handshake.chainKey[:])
	setZero(handshake.hash[:]) // Doesn't necessarily need to be zeroed. Could be used for something interesting down the line.
	setZero(handshake.localEphemeral[:])
	peer.handshake.state = handshakeZeroed

	// create AEAD instances

	keypair := new(Keypair)
        keypair.send = sendKey
        keypair.receive = recvKey

        setZero(sendKey[:])
	setZero(recvKey[:])

        keypair.created = time.Now()
	keypair.replayFilter.Reset()
	keypair.isInitiator = isInitiator
	keypair.localIndex = peer.handshake.localIndex
	keypair.remoteIndex = peer.handshake.remoteIndex

	// remap index

	device.indexTable.SwapIndexForKeypair(handshake.localIndex, keypair)
	handshake.localIndex = 0

	// rotate key pairs

	keypairs := &peer.keypairs
	keypairs.Lock()
	defer keypairs.Unlock()

	previous := keypairs.previous
	next := keypairs.next.Load()
	current := keypairs.current

	if isInitiator {
		if next != nil {
			keypairs.next.Store(nil)
			keypairs.previous = next
			device.DeleteKeypair(current)
		} else {
			keypairs.previous = current
		}
		device.DeleteKeypair(previous)
		keypairs.current = keypair
	} else {
		keypairs.next.Store(keypair)
		device.DeleteKeypair(next)
		keypairs.previous = nil
		device.DeleteKeypair(previous)
	}

	return nil
}

func (peer *Peer) ReceivedWithKeypair(receivedKeypair *Keypair) bool {
	keypairs := &peer.keypairs

	if keypairs.next.Load() != receivedKeypair {
		return false
	}
	keypairs.Lock()
	defer keypairs.Unlock()
	if keypairs.next.Load() != receivedKeypair {
		return false
	}
	old := keypairs.previous
	keypairs.previous = keypairs.current
	peer.device.DeleteKeypair(old)
	keypairs.current = keypairs.next.Load()
	keypairs.next.Store(nil)
	return true
}
