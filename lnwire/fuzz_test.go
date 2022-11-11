package lnwire

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

// prefixWithMsgType takes []byte and adds a wire protocol prefix
// to make the []byte into an actual message to be used in fuzzing.
func prefixWithMsgType(data []byte, prefix MessageType) []byte {
	var prefixBytes [2]byte
	binary.BigEndian.PutUint16(prefixBytes[:], uint16(prefix))
	data = append(prefixBytes[:], data...)

	return data
}

// harness performs the actual fuzz testing of the appropriate wire message.
// This function will check that the passed-in message passes wire length
// checks, is a valid message once deserialized, and passes a sequence of
// serialization and deserialization checks.
func harness(t *testing.T, data []byte) {
	t.Helper()

	// Create a reader with the byte array.
	r := bytes.NewReader(data)

	// Check that the created message is not greater than the maximum
	// message size.
	if len(data) > MaxSliceLength {
		return
	}

	msg, err := ReadMessage(r, 0)
	if err != nil {
		return
	}

	// We will serialize the message into a new bytes buffer.
	var b bytes.Buffer
	_, err = WriteMessage(&b, msg, 0)
	require.NoError(t, err)

	// Deserialize the message from the serialized bytes buffer, and then
	// assert that the original message is equal to the newly deserialized
	// message.
	newMsg, err := ReadMessage(&b, 0)
	require.NoError(t, err)
	require.Equal(t, msg, newMsg)
}

func FuzzAcceptChannel(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		data = prefixWithMsgType(data, MsgAcceptChannel)
		// Create a reader with the byte array.
		r := bytes.NewReader(data)

		// Make sure byte array length (excluding 2 bytes for message
		// type) is less than max payload size for the wire message.
		payloadLen := uint32(len(data)) - 2
		if payloadLen > MaxMsgBody {
			return
		}

		msg, err := ReadMessage(r, 0)
		if err != nil {
			return
		}

		// We will serialize the message into a new bytes buffer.
		var b bytes.Buffer
		_, err = WriteMessage(&b, msg, 0)
		require.NoError(t, err)

		// Deserialize the message from the serialized bytes buffer, and
		// then assert that the original message is equal to the newly
		// deserialized message.
		newMsg, err := ReadMessage(&b, 0)
		require.NoError(t, err)

		require.IsType(t, &AcceptChannel{}, msg)
		first, _ := msg.(*AcceptChannel)
		require.IsType(t, &AcceptChannel{}, newMsg)
		second, _ := newMsg.(*AcceptChannel)

		// We can't use require.Equal for UpfrontShutdownScript, since
		// we consider the empty slice and nil to be equivalent.
		require.True(
			t, bytes.Equal(
				first.UpfrontShutdownScript,
				second.UpfrontShutdownScript,
			),
		)
		first.UpfrontShutdownScript = nil
		second.UpfrontShutdownScript = nil

		require.Equal(t, first, second)
	})
}

func FuzzAnnounceSignatures(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgAnnounceSignatures.
		data = prefixWithMsgType(data, MsgAnnounceSignatures)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzChannelAnnouncement(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgChannelAnnouncement.
		data = prefixWithMsgType(data, MsgChannelAnnouncement)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzChannelReestablish(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgChannelReestablish.
		data = prefixWithMsgType(data, MsgChannelReestablish)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzChannelUpdate(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgChannelUpdate.
		data = prefixWithMsgType(data, MsgChannelUpdate)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzClosingSigned(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgClosingSigned.
		data = prefixWithMsgType(data, MsgClosingSigned)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzCommitSig(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgCommitSig.
		data = prefixWithMsgType(data, MsgCommitSig)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzError(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgError.
		data = prefixWithMsgType(data, MsgError)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzWarning(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgWarning.
		data = prefixWithMsgType(data, MsgWarning)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzFundingCreated(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgFundingCreated.
		data = prefixWithMsgType(data, MsgFundingCreated)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzChannelReady(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgChannelReady.
		data = prefixWithMsgType(data, MsgChannelReady)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzFundingSigned(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgFundingSigned.
		data = prefixWithMsgType(data, MsgFundingSigned)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzGossipTimestampRange(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgGossipTimestampRange.
		data = prefixWithMsgType(data, MsgGossipTimestampRange)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzInit(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgInit.
		data = prefixWithMsgType(data, MsgInit)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzNodeAnnouncement(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgNodeAnnouncement.
		data = prefixWithMsgType(data, MsgNodeAnnouncement)

		// We have to do this here instead of in harness so that
		// reflect.DeepEqual isn't called. Address (de)serialization
		// messes up the fuzzing assertions.

		// Create a reader with the byte array.
		r := bytes.NewReader(data)

		// Make sure byte array length (excluding 2 bytes for message
		// type) is less than max payload size for the wire message.
		payloadLen := uint32(len(data)) - 2
		if payloadLen > MaxMsgBody {
			return
		}

		msg, err := ReadMessage(r, 0)
		if err != nil {
			return
		}

		// We will serialize the message into a new bytes buffer.
		var b bytes.Buffer
		_, err = WriteMessage(&b, msg, 0)
		require.NoError(t, err)

		// Deserialize the message from the serialized bytes buffer, and
		// then assert that the original message is equal to the newly
		// deserialized message.
		newMsg, err := ReadMessage(&b, 0)
		require.NoError(t, err)

		require.IsType(t, &NodeAnnouncement{}, msg)
		first, _ := msg.(*NodeAnnouncement)
		require.IsType(t, &NodeAnnouncement{}, newMsg)
		second, _ := newMsg.(*NodeAnnouncement)

		// We can't use require.Equal for Addresses, since the same IP
		// can be represented by different underlying bytes. Instead, we
		// compare the normalized string representation of each address.
		require.Equal(t, len(first.Addresses), len(second.Addresses))
		for i := range first.Addresses {
			require.Equal(
				t, first.Addresses[i].String(),
				second.Addresses[i].String(),
			)
		}
		first.Addresses = nil
		second.Addresses = nil

		require.Equal(t, first, second)
	})
}

func FuzzOpenChannel(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgOpenChannel.
		data = prefixWithMsgType(data, MsgOpenChannel)

		// We have to do this here instead of in harness so that
		// reflect.DeepEqual isn't called. Because of the
		// UpfrontShutdownScript encoding, the first message and second
		// message aren't deeply equal since the first has a nil slice
		// and the other has an empty slice.

		// Create a reader with the byte array.
		r := bytes.NewReader(data)

		// Make sure byte array length (excluding 2 bytes for message
		// type) is less than max payload size for the wire message.
		payloadLen := uint32(len(data)) - 2
		if payloadLen > MaxMsgBody {
			return
		}

		msg, err := ReadMessage(r, 0)
		if err != nil {
			return
		}

		// We will serialize the message into a new bytes buffer.
		var b bytes.Buffer
		_, err = WriteMessage(&b, msg, 0)
		require.NoError(t, err)

		// Deserialize the message from the serialized bytes buffer, and
		// then assert that the original message is equal to the newly
		// deserialized message.
		newMsg, err := ReadMessage(&b, 0)
		require.NoError(t, err)

		require.IsType(t, &OpenChannel{}, msg)
		first, _ := msg.(*OpenChannel)
		require.IsType(t, &OpenChannel{}, newMsg)
		second, _ := newMsg.(*OpenChannel)

		// We can't use require.Equal for UpfrontShutdownScript, since
		// we consider the empty slice and nil to be equivalent.
		require.True(
			t, bytes.Equal(
				first.UpfrontShutdownScript,
				second.UpfrontShutdownScript,
			),
		)
		first.UpfrontShutdownScript = nil
		second.UpfrontShutdownScript = nil

		require.Equal(t, first, second)
	})
}

func FuzzOpenChannel2(f *testing.F) {
	// This seed is a valid open_channel2 message generated by CLN.
	seed, err := hex.DecodeString("06226e46111a0b59caaf126043eb5bbf28c34f" +
		"3a5e332a1fc7b2b73cf188910f2aa51d05d2a4cc27183fcdc3f78cb87812" +
		"a617d8b843369e3c7bb51222898db200001d4c00001d4c00000000000186" +
		"a00000000000000222ffffffffffffffff0000000000000000000501e300" +
		"00006602324266de8403b3ab157a09f1f784d587af61831c998c151bcc21" +
		"bb74c2b2314b02eb546006587442551b7f1c08e6336998d3ffafe1bedea9" +
		"2aaff9ba03bc3d02e6022dbc0053dd6f3310d84e55eebaacfad53fe3e3ec" +
		"3c2cecb1cffebdd95fa8063f03b5aa92c890a616a425948f6eef8be810e7" +
		"b65d1a6fe5bf5df62d83e1727f81d602346928c7642a1098a328e2787254" +
		"c060f03a6b2c06af78a128868f913945d447029f443a7d1cb0f003caf78b" +
		"9d5b7edef51fd7745b43a1b921b6f22ce748bfeb50010000")
	if err != nil {
		f.Error("failed to decode seed")
	}
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgOpenChannel2.
		data = prefixWithMsgType(data, MsgOpenChannel2)

		// We have to do this here instead of in harness so that
		// reflect.DeepEqual isn't called. Because of the
		// UpfrontShutdownScript encoding, the first message and second
		// message aren't deeply equal since the first has a nil slice
		// and the other has an empty slice.

		// Create a reader with the byte array.
		r := bytes.NewReader(data)

		// Make sure byte array length (excluding 2 bytes for message
		// type) is less than max payload size for the wire message.
		payloadLen := uint32(len(data)) - 2
		if payloadLen > MaxMsgBody {
			return
		}

		msg, err := ReadMessage(r, 0)
		if err != nil {
			return
		}

		// We will serialize the message into a new bytes buffer.
		var b bytes.Buffer
		if _, err := WriteMessage(&b, msg, 0); err != nil {
			// Could not serialize message into bytes buffer, panic
			t.Fatal(err)
		}

		// Deserialize the message from the serialized bytes buffer, and
		// then assert that the original message is equal to the newly
		// deserialized message.
		newMsg, err := ReadMessage(&b, 0)
		if err != nil {
			// Could not deserialize message from bytes buffer,
			// panic
			t.Fatal(err)
		}

		// Now compare every field instead of using reflect.DeepEqual.
		// For UpfrontShutdownScript, we only compare bytes. This
		// probably takes up more branches than necessary, but that's
		// fine for now.
		var shouldPanic bool
		first, ok := msg.(*OpenChannel2)
		if !ok {
			t.Fatal("first message is not OpenChannel2")
		}
		second, ok := newMsg.(*OpenChannel2)
		if !ok {
			t.Fatal("second message is not OpenChannel2")
		}

		if !first.ChainHash.IsEqual(&second.ChainHash) {
			shouldPanic = true
		}

		if !bytes.Equal(first.PendingChannelID[:],
			second.PendingChannelID[:]) {

			shouldPanic = true
		}

		if first.FundingFeePerKWeight != second.FundingFeePerKWeight {
			shouldPanic = true
		}

		if first.CommitFeePerKWeight != second.CommitFeePerKWeight {
			shouldPanic = true
		}

		if first.FundingAmount != second.FundingAmount {
			shouldPanic = true
		}

		if first.DustLimit != second.DustLimit {
			shouldPanic = true
		}

		if first.MaxValueInFlight != second.MaxValueInFlight {
			shouldPanic = true
		}

		if first.HtlcMinimum != second.HtlcMinimum {
			shouldPanic = true
		}

		if first.CsvDelay != second.CsvDelay {
			shouldPanic = true
		}

		if first.MaxAcceptedHTLCs != second.MaxAcceptedHTLCs {
			shouldPanic = true
		}

		if first.LockTime != second.LockTime {
			shouldPanic = true
		}

		if !first.FundingKey.IsEqual(second.FundingKey) {
			shouldPanic = true
		}

		if !first.RevocationPoint.IsEqual(second.RevocationPoint) {
			shouldPanic = true
		}

		if !first.PaymentPoint.IsEqual(second.PaymentPoint) {
			shouldPanic = true
		}

		if !first.DelayedPaymentPoint.IsEqual(
			second.DelayedPaymentPoint) {

			shouldPanic = true
		}

		if !first.HtlcPoint.IsEqual(second.HtlcPoint) {
			shouldPanic = true
		}

		if !first.FirstCommitmentPoint.IsEqual(
			second.FirstCommitmentPoint) {

			shouldPanic = true
		}

		if first.ChannelFlags != second.ChannelFlags {
			shouldPanic = true
		}

		if !bytes.Equal(first.UpfrontShutdownScript,
			second.UpfrontShutdownScript) {

			shouldPanic = true
		}

		if !reflect.DeepEqual(first.ChannelType, second.ChannelType) {
			shouldPanic = true
		}

		if !reflect.DeepEqual(first.LeaseExpiry, second.LeaseExpiry) {
			shouldPanic = true
		}

		if shouldPanic {
			t.Fatal("original message and deserialized message " +
				"are not equal")
		}
	})
}

func FuzzPing(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgPing.
		data = prefixWithMsgType(data, MsgPing)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzPong(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgPong.
		data = prefixWithMsgType(data, MsgPong)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzQueryChannelRange(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgQueryChannelRange.
		data = prefixWithMsgType(data, MsgQueryChannelRange)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzZlibQueryShortChanIDs(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var buf bytes.Buffer
		zlibWriter := zlib.NewWriter(&buf)
		_, err := zlibWriter.Write(data)
		require.NoError(t, err) // Zlib bug?

		err = zlibWriter.Close()
		require.NoError(t, err) // Zlib bug?

		compressedPayload := buf.Bytes()

		chainhash := []byte("00000000000000000000000000000000")
		numBytesInBody := len(compressedPayload) + 1
		zlibByte := []byte("\x01")

		bodyBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(bodyBytes, uint16(numBytesInBody))

		payload := chainhash
		payload = append(payload, bodyBytes...)
		payload = append(payload, zlibByte...)
		payload = append(payload, compressedPayload...)

		// Prefix with MsgQueryShortChanIDs.
		payload = prefixWithMsgType(payload, MsgQueryShortChanIDs)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, payload)
	})
}

func FuzzQueryShortChanIDs(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgQueryShortChanIDs.
		data = prefixWithMsgType(data, MsgQueryShortChanIDs)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzZlibReplyChannelRange(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var buf bytes.Buffer
		zlibWriter := zlib.NewWriter(&buf)
		_, err := zlibWriter.Write(data)
		require.NoError(t, err) // Zlib bug?

		err = zlibWriter.Close()
		require.NoError(t, err) // Zlib bug?

		compressedPayload := buf.Bytes()

		// Initialize some []byte vars which will prefix our payload
		chainhash := []byte("00000000000000000000000000000000")
		firstBlockHeight := []byte("\x00\x00\x00\x00")
		numBlocks := []byte("\x00\x00\x00\x00")
		completeByte := []byte("\x00")

		numBytesInBody := len(compressedPayload) + 1
		zlibByte := []byte("\x01")

		bodyBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(bodyBytes, uint16(numBytesInBody))

		payload := chainhash
		payload = append(payload, firstBlockHeight...)
		payload = append(payload, numBlocks...)
		payload = append(payload, completeByte...)
		payload = append(payload, bodyBytes...)
		payload = append(payload, zlibByte...)
		payload = append(payload, compressedPayload...)

		// Prefix with MsgReplyChannelRange.
		payload = prefixWithMsgType(payload, MsgReplyChannelRange)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, payload)
	})
}

func FuzzReplyChannelRange(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgReplyChannelRange.
		data = prefixWithMsgType(data, MsgReplyChannelRange)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzReplyShortChanIDsEnd(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgReplyShortChanIDsEnd.
		data = prefixWithMsgType(data, MsgReplyShortChanIDsEnd)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzRevokeAndAck(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgRevokeAndAck.
		data = prefixWithMsgType(data, MsgRevokeAndAck)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzShutdown(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgShutdown.
		data = prefixWithMsgType(data, MsgShutdown)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzUpdateAddHTLC(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgUpdateAddHTLC.
		data = prefixWithMsgType(data, MsgUpdateAddHTLC)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzUpdateFailHTLC(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgUpdateFailHTLC.
		data = prefixWithMsgType(data, MsgUpdateFailHTLC)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzUpdateFailMalformedHTLC(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgUpdateFailMalformedHTLC.
		data = prefixWithMsgType(data, MsgUpdateFailMalformedHTLC)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzUpdateFee(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgUpdateFee.
		data = prefixWithMsgType(data, MsgUpdateFee)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzUpdateFulfillHTLC(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with MsgUpdateFulFillHTLC.
		data = prefixWithMsgType(data, MsgUpdateFulfillHTLC)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzDynPropose(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with DynPropose.
		data = prefixWithMsgType(data, MsgDynPropose)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzDynReject(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with DynReject.
		data = prefixWithMsgType(data, MsgDynReject)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzDynAck(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with DynReject.
		data = prefixWithMsgType(data, MsgDynAck)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzKickoffSig(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with KickoffSig
		data = prefixWithMsgType(data, MsgKickoffSig)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzCustomMessage(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, customMessageType uint16) {
		if customMessageType < uint16(CustomTypeStart) {
			customMessageType += uint16(CustomTypeStart)
		}

		// Prefix with CustomMessage.
		data = prefixWithMsgType(data, MessageType(customMessageType))

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

// FuzzParseRawSignature tests that our DER-encoded signature parsing does not
// panic for arbitrary inputs and that serializing and reparsing the signatures
// does not mutate them.
func FuzzParseRawSignature(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		sig, err := NewSigFromECDSARawSignature(data)
		if err != nil {
			return
		}

		sig2, err := NewSigFromECDSARawSignature(sig.ToSignatureBytes())
		require.NoError(t, err, "failed to reparse signature")

		require.Equal(t, sig, sig2, "signature mismatch")
	})
}

// FuzzConvertFixedSignature tests that conversion of fixed 64-byte signatures
// to DER-encoded signatures does not panic and that parsing and reconverting
// the signatures does not mutate them.
func FuzzConvertFixedSignature(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var sig Sig
		if len(data) > len(sig.bytes[:]) {
			return
		}
		copy(sig.bytes[:], data)

		derSig, err := sig.ToSignature()
		if err != nil {
			return
		}

		sig2, err := NewSigFromSignature(derSig)
		require.NoError(t, err, "failed to parse signature")

		derSig2, err := sig2.ToSignature()
		require.NoError(t, err, "failed to reconvert signature to DER")

		derBytes := derSig.Serialize()
		derBytes2 := derSig2.Serialize()
		require.Equal(t, derBytes, derBytes2, "signature mismatch")
	})
}

// prefixWithFailCode adds a failure code prefix to data.
func prefixWithFailCode(data []byte, code FailCode) []byte {
	var codeBytes [2]byte
	binary.BigEndian.PutUint16(codeBytes[:], uint16(code))
	data = append(codeBytes[:], data...)

	return data
}

// equalFunc is a function used to determine whether two deserialized messages
// are equivalent.
type equalFunc func(x, y any) bool

// onionFailureHarnessCustom performs the actual fuzz testing of the appropriate
// onion failure message. This function will check that the passed-in message
// passes wire length checks, is a valid message once deserialized, and passes a
// sequence of serialization and deserialization checks.
func onionFailureHarnessCustom(t *testing.T, data []byte, code FailCode,
	eq equalFunc) {

	data = prefixWithFailCode(data, code)

	// Don't waste time fuzzing messages larger than we'll ever accept.
	if len(data) > MaxSliceLength {
		return
	}

	// First check whether the failure message can be decoded.
	r := bytes.NewReader(data)
	msg, err := DecodeFailureMessage(r, 0)
	if err != nil {
		return
	}

	// We now have a valid decoded message. Verify that encoding and
	// decoding the message does not mutate it.

	var b bytes.Buffer
	err = EncodeFailureMessage(&b, msg, 0)
	require.NoError(t, err, "failed to encode failure message")

	newMsg, err := DecodeFailureMessage(&b, 0)
	require.NoError(t, err, "failed to decode serialized failure message")

	require.True(
		t, eq(msg, newMsg),
		"original message and deserialized message are not equal: "+
			"%v != %v",
		msg, newMsg,
	)

	// Now verify that encoding/decoding full packets works as expected.

	var pktBuf bytes.Buffer
	if err := EncodeFailure(&pktBuf, msg, 0); err != nil {
		// EncodeFailure returns an error if the encoded message would
		// exceed FailureMessageLength bytes, as LND always encodes
		// fixed-size packets for privacy. But it is valid to decode
		// messages longer than this, so we should not report an error
		// if the original message was longer.
		//
		// We add 2 to the length of the original message since it may
		// have omitted a channel_update type prefix of 2 bytes. When
		// we re-encode such a message, we will add the 2-byte prefix
		// as prescribed by the spec.
		if len(data)+2 > FailureMessageLength {
			return
		}

		t.Fatalf("failed to encode failure packet: %v", err)
	}

	// We should use FailureMessageLength sized packets plus 2 bytes to
	// encode the message length and 2 bytes to encode the padding length,
	// as recommended by the spec.
	require.Equal(
		t, pktBuf.Len(), FailureMessageLength+4,
		"wrong failure message length",
	)

	pktMsg, err := DecodeFailure(&pktBuf, 0)
	require.NoError(t, err, "failed to decode failure packet")

	require.True(
		t, eq(msg, pktMsg),
		"original message and decoded packet message are not equal: "+
			"%v != %v",
		msg, pktMsg,
	)
}

func onionFailureHarness(t *testing.T, data []byte, code FailCode) {
	t.Helper()
	onionFailureHarnessCustom(t, data, code, reflect.DeepEqual)
}

func FuzzFailIncorrectDetails(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Since FailIncorrectDetails.Decode can leave extraOpaqueData
		// as nil while FailIncorrectDetails.Encode writes an empty
		// slice, we need to use a custom equality function.
		eq := func(x, y any) bool {
			msg1, ok := x.(*FailIncorrectDetails)
			require.True(
				t, ok, "msg1 was not FailIncorrectDetails",
			)

			msg2, ok := y.(*FailIncorrectDetails)
			require.True(
				t, ok, "msg2 was not FailIncorrectDetails",
			)

			return msg1.amount == msg2.amount &&
				msg1.height == msg2.height &&
				bytes.Equal(
					msg1.extraOpaqueData,
					msg2.extraOpaqueData,
				)
		}

		onionFailureHarnessCustom(
			t, data, CodeIncorrectOrUnknownPaymentDetails, eq,
		)
	})
}

func FuzzFailInvalidOnionVersion(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		onionFailureHarness(t, data, CodeInvalidOnionVersion)
	})
}

func FuzzFailInvalidOnionHmac(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		onionFailureHarness(t, data, CodeInvalidOnionHmac)
	})
}

func FuzzFailInvalidOnionKey(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		onionFailureHarness(t, data, CodeInvalidOnionKey)
	})
}

func FuzzFailTemporaryChannelFailure(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		onionFailureHarness(t, data, CodeTemporaryChannelFailure)
	})
}

func FuzzFailAmountBelowMinimum(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		onionFailureHarness(t, data, CodeAmountBelowMinimum)
	})
}

func FuzzFailFeeInsufficient(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		onionFailureHarness(t, data, CodeFeeInsufficient)
	})
}

func FuzzFailIncorrectCltvExpiry(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		onionFailureHarness(t, data, CodeIncorrectCltvExpiry)
	})
}

func FuzzFailExpiryTooSoon(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		onionFailureHarness(t, data, CodeExpiryTooSoon)
	})
}

func FuzzFailChannelDisabled(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		onionFailureHarness(t, data, CodeChannelDisabled)
	})
}

func FuzzFailFinalIncorrectCltvExpiry(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		onionFailureHarness(t, data, CodeFinalIncorrectCltvExpiry)
	})
}

func FuzzFailFinalIncorrectHtlcAmount(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		onionFailureHarness(t, data, CodeFinalIncorrectHtlcAmount)
	})
}

func FuzzInvalidOnionPayload(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		onionFailureHarness(t, data, CodeInvalidOnionPayload)
	})
}

func FuzzClosingSig(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with ClosingSig.
		data = prefixWithMsgType(data, MsgClosingSig)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}

func FuzzClosingComplete(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Prefix with ClosingComplete.
		data = prefixWithMsgType(data, MsgClosingComplete)

		// Pass the message into our general fuzz harness for wire
		// messages!
		harness(t, data)
	})
}
