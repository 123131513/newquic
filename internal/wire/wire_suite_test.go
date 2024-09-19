package wire

import (
	"bytes"

	"github.com/123131513/newquic/internal/protocol"
	"github.com/123131513/newquic/internal/utils"
	"github.com/123131513/newquic/quicvarint"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestCrypto(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Wire Suite")
}

const (
	versionLittleEndian = protocol.Version37 // a QUIC version that uses little endian encoding
	versionBigEndian    = protocol.Version39 // a QUIC version that uses big endian encoding
	// a QUIC version that uses the IETF frame types
	versionIETFFrames = protocol.VersionTLS
)

var _ = BeforeSuite(func() {
	Expect(utils.GetByteOrder(versionLittleEndian)).To(Equal(utils.LittleEndian))
	Expect(utils.GetByteOrder(versionBigEndian)).To(Equal(utils.BigEndian))
})

func encodeVarInt(i uint64) []byte {
	b := &bytes.Buffer{}
	quicvarint.Write(b, i)
	return b.Bytes()
}
