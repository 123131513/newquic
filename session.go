package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/123131513/newquic/ackhandler"
	"github.com/123131513/newquic/congestion"
	"github.com/123131513/newquic/internal/flowcontrol"
	"github.com/123131513/newquic/internal/handshake"
	"github.com/123131513/newquic/internal/protocol"
	"github.com/123131513/newquic/internal/utils"
	"github.com/123131513/newquic/internal/wire"
	"github.com/123131513/newquic/qerr"
)

type unpacker interface {
	Unpack(publicHeaderBinary []byte, hdr *wire.PublicHeader, data []byte) (*unpackedPacket, error)
}

type receivedPacket struct {
	remoteAddr   net.Addr
	publicHeader *wire.PublicHeader
	data         []byte
	rcvTime      time.Time
	rcvPconn     net.PacketConn
}

var (
	errRstStreamOnInvalidStream   = errors.New("RST_STREAM received for unknown stream")
	errWindowUpdateOnClosedStream = errors.New("WINDOW_UPDATE received for an already closed stream")
)

var (
	newCryptoSetup       = handshake.NewCryptoSetup
	newCryptoSetupClient = handshake.NewCryptoSetupClient
)

type handshakeEvent struct {
	encLevel protocol.EncryptionLevel
	err      error
}

type closeError struct {
	err    error
	remote bool
}

// zzh: add PacketBufferPool
// PacketInfo stores metadata about each packet.
type PacketInfo struct {
	IsStart         bool
	IsEnd           bool
	SequenceID      int
	Processed       bool
	Packetsize      int
	BlockSize       int
	BlockSequenceID int
}

// PacketBuffer manages packets and their metadata.
type PacketBuffer struct {
	mu              sync.Mutex
	mr              sync.Mutex
	s               *session
	sequence_buffer map[int]PacketInfo
	data_buffer     map[int]*wire.DatagramFrame
	frameToInfo     map[*wire.DatagramFrame]PacketInfo
	timers          map[int]*time.Timer
	retranstimers   map[int]*time.Timer
}

// NewPacketBuffer creates a new PacketBuffer.
func NewPacketBuffer(s *session) *PacketBuffer {
	return &PacketBuffer{
		s:               s,
		sequence_buffer: make(map[int]PacketInfo),
		data_buffer:     make(map[int]*wire.DatagramFrame),
		frameToInfo:     make(map[*wire.DatagramFrame]PacketInfo),
		timers:          make(map[int]*time.Timer),
		retranstimers:   make(map[int]*time.Timer),
	}
}

// AddPacket adds a packet and its metadata to the buffer.
func (pb *PacketBuffer) AddPacket(frame *wire.DatagramFrame, info PacketInfo) {
	fmt.Println("AddPacket")
	pb.mu.Lock()
	defer pb.mu.Unlock()

	// 添加数据包到缓冲区
	pb.sequence_buffer[info.SequenceID] = info
	pb.data_buffer[info.SequenceID] = frame
	pb.frameToInfo[frame] = info

	fmt.Println("AddPacket  2")
	if info.IsEnd {
		timer := time.AfterFunc(10000*time.Millisecond, func() {
			pb.clearBlock(info.BlockSequenceID)
		})
		pb.timers[info.BlockSequenceID] = timer
		retranstimers := time.AfterFunc(80*time.Millisecond, func() {
			pb.RetransmissionBlock(info.BlockSequenceID)
		})
		pb.retranstimers[info.BlockSequenceID] = retranstimers
	}

	// 打开或创建日志文件
	file, err := os.OpenFile("quic_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		return
	}
	defer file.Close()

	// 写入数据包信息到日志文件
	logEntry := fmt.Sprintf("SequenceID: %d, IsStart: %t, IsEnd: %t, Packetsize: %d, BlockSize: %d, BlockStartSequenceID: %d\n",
		info.SequenceID, info.IsStart, info.IsEnd, info.Packetsize, info.BlockSize, info.BlockSequenceID)
	if _, err := file.WriteString(logEntry); err != nil {
		fmt.Printf("Error writing to log file: %v\n", err)
	}
}

// AddPacket adds a packet and its metadata to the buffer.
func (pb *PacketBuffer) Refreshinfonolog(frame *wire.DatagramFrame, info PacketInfo) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	// 添加数据包到缓冲区
	pb.sequence_buffer[info.SequenceID] = info
	pb.frameToInfo[frame] = info
}

// GetPacket retrieves a packet and its metadata from the buffer.
func (pb *PacketBuffer) GetPacket(sequenceID int) (*wire.DatagramFrame, PacketInfo, error) {
	fmt.Println("GetPacket")
	pb.mu.Lock()
	defer pb.mu.Unlock()

	frame, dataExists := pb.data_buffer[sequenceID]
	fmt.Println("GetPacket 2")
	info, infoExists := pb.sequence_buffer[sequenceID]
	if !dataExists || !infoExists {
		return nil, PacketInfo{}, errors.New("packet not found")
	}
	return frame, info, nil
}

func (pb *PacketBuffer) GetPacketInfoByFrame(frame *wire.DatagramFrame) (PacketInfo, error) {
	fmt.Println("GetPacketInfoByFrame")
	pb.mu.Lock()
	defer pb.mu.Unlock()

	info, exists := pb.frameToInfo[frame]
	fmt.Println("GetPacketInfoByFrame 2")
	if !exists {
		return PacketInfo{}, fmt.Errorf("packet info for frame not found")
	}

	return info, nil
}

func (pb *PacketBuffer) clearBlock(blockSequenceID int) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	for seqID, info := range pb.sequence_buffer {
		if info.BlockSequenceID == blockSequenceID {
			delete(pb.data_buffer, seqID)
			delete(pb.sequence_buffer, seqID)
		}
	}

	if timer, exists := pb.timers[blockSequenceID]; exists {
		timer.Stop()
		delete(pb.timers, blockSequenceID)
	}

	fmt.Printf("Cleared block with BlockSequenceID: %d\n", blockSequenceID)
}

func (pb *PacketBuffer) RetransmissionBlock(blockSequenceID int) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	for seqID, info := range pb.sequence_buffer {
		// for _, info := range pb.sequence_buffer {
		if info.BlockSequenceID == blockSequenceID && !info.Processed {
			fmt.Printf(" Retransmission frame with SequenceID: %d\n", info.SequenceID)
			// _, exists := pb.data_buffer[seqID]
			frame, exists := pb.data_buffer[seqID]
			if !exists {
				fmt.Printf("Frame not found in data_buffer for SequenceID: %d\n", seqID)
				continue
			}
			pb.s.datagramQueue.AddToRetransmissionQueue(frame)
			fmt.Printf(" Retransmission block with BlockSequenceID: %d\n", blockSequenceID)
			info.Processed = true
		}
		if info.BlockSequenceID > blockSequenceID || (info.IsEnd && info.BlockSequenceID == blockSequenceID) {
			break
		}
	}

	// 重置重传计时器
	if timer, exists := pb.retranstimers[blockSequenceID]; exists {
		timer.Stop()
		// delete(pb.retranstimers, blockSequenceID)
	}
	// retranstimer := time.AfterFunc(60*time.Millisecond, func() {
	// 	pb.RetransmissionBlock(blockSequenceID)
	// })
	// pb.retranstimers[blockSequenceID] = retranstimer

}

// A Session is a QUIC session
type session struct {
	connectionID protocol.ConnectionID
	perspective  protocol.Perspective
	version      protocol.VersionNumber
	config       *Config

	paths       map[protocol.PathID]*path
	closedPaths map[protocol.PathID]bool
	pathsLock   sync.RWMutex

	createPaths bool

	streamsMap *streamsMap

	rttStats *congestion.RTTStats

	remoteRTTs         map[protocol.PathID]time.Duration
	lastPathsFrameSent time.Time

	streamFramer *streamFramer

	flowControlManager flowcontrol.FlowControlManager

	unpacker unpacker
	packer   *packetPacker

	peerBlocked bool

	cryptoSetup handshake.CryptoSetup

	receivedPackets  chan *receivedPacket
	sendingScheduled chan struct{}
	// closeChan is used to notify the run loop that it should terminate.
	closeChan chan closeError
	closeOnce sync.Once

	ctx       context.Context
	ctxCancel context.CancelFunc

	// when we receive too many undecryptable packets during the handshake, we send a Public reset
	// but only after a time of protocol.PublicResetTimeout has passed
	undecryptablePackets                   []*receivedPacket
	receivedTooManyUndecrytablePacketsTime time.Time

	// this channel is passed to the CryptoSetup and receives the current encryption level
	// it is closed as soon as the handshake is complete
	aeadChanged       <-chan protocol.EncryptionLevel
	handshakeComplete bool
	// will be closed as soon as the handshake completes, and receive any error that might occur until then
	// it is used to block WaitUntilHandshakeComplete()
	handshakeCompleteChan chan error
	// handshakeChan receives handshake events and is closed as soon the handshake completes
	// the receiving end of this channel is passed to the creator of the session
	// it receives at most 3 handshake events: 2 when the encryption level changes, and one error
	handshakeChan chan<- handshakeEvent

	connectionParameters handshake.ConnectionParametersManager

	sessionCreationTime     time.Time
	lastNetworkActivityTime time.Time

	timer *utils.Timer
	// keepAlivePingSent stores whether a Ping frame was sent to the peer or not
	// it is reset as soon as we receive a packet from the peer
	keepAlivePingSent bool

	pathTimers chan *path

	pathManager         *pathManager
	pathManagerLaunched bool

	scheduler *scheduler
	// zzh: for the scheduler deadline
	exceed_deadline utils.AtomicBool
	// zzh: datagram queue
	datagramQueue *datagramQueue
	// zzh: datagram max frame size
	MaxDatagramFrameSize protocol.ByteCount
	// zzh: add the logger
	logger utils.Logger
	// zzh: add packet buffer
	packetBuffer                *PacketBuffer
	sequenceID                  int  // 添加序列ID字段
	nextIsStart                 bool // 添加标记字段
	currentBlockSize            int  // 当前块的大小
	currentBlockStartSequenceID int  // 当前块的起始序号
}

var _ Session = &session{}

// newSession makes a new session
func newSession(
	conn connection,
	pconnMgr *pconnManager,
	createPaths bool,
	v protocol.VersionNumber,
	connectionID protocol.ConnectionID,
	sCfg *handshake.ServerConfig,
	tlsConf *tls.Config,
	config *Config,
) (packetHandler, <-chan handshakeEvent, error) {
	s := &session{
		paths:        make(map[protocol.PathID]*path),
		closedPaths:  make(map[protocol.PathID]bool),
		createPaths:  createPaths,
		remoteRTTs:   make(map[protocol.PathID]time.Duration),
		connectionID: connectionID,
		perspective:  protocol.PerspectiveServer,
		version:      v,
		config:       config,
	}
	return s.setup(sCfg, "", tlsConf, nil, conn, pconnMgr)
}

// declare this as a variable, such that we can it mock it in the tests
var newClientSession = func(
	conn connection,
	pconnMgr *pconnManager,
	createPaths bool,
	hostname string,
	v protocol.VersionNumber,
	connectionID protocol.ConnectionID,
	tlsConf *tls.Config,
	config *Config,
	negotiatedVersions []protocol.VersionNumber,
) (packetHandler, <-chan handshakeEvent, error) {
	s := &session{
		paths:        make(map[protocol.PathID]*path),
		closedPaths:  make(map[protocol.PathID]bool),
		createPaths:  createPaths,
		remoteRTTs:   make(map[protocol.PathID]time.Duration),
		connectionID: connectionID,
		perspective:  protocol.PerspectiveClient,
		version:      v,
		config:       config,
	}
	return s.setup(nil, hostname, tlsConf, negotiatedVersions, conn, pconnMgr)
}

func (s *session) setup(
	scfg *handshake.ServerConfig,
	hostname string,
	tlsConf *tls.Config,
	negotiatedVersions []protocol.VersionNumber,
	conn connection,
	pconnMgr *pconnManager,
) (packetHandler, <-chan handshakeEvent, error) {
	aeadChanged := make(chan protocol.EncryptionLevel, 2)
	s.aeadChanged = aeadChanged
	handshakeChan := make(chan handshakeEvent, 3)
	s.handshakeChan = handshakeChan
	s.handshakeCompleteChan = make(chan error, 1)
	s.receivedPackets = make(chan *receivedPacket, protocol.MaxSessionUnprocessedPackets)
	s.closeChan = make(chan closeError, 1)
	s.sendingScheduled = make(chan struct{}, 1)
	s.undecryptablePackets = make([]*receivedPacket, 0, protocol.MaxUndecryptablePackets)
	s.ctx, s.ctxCancel = context.WithCancel(context.Background())

	s.timer = utils.NewTimer()
	now := time.Now()
	s.lastNetworkActivityTime = now
	s.sessionCreationTime = now

	s.connectionParameters = handshake.NewConnectionParamatersManager(
		s.perspective,
		s.version,
		protocol.ByteCount(s.config.MaxReceiveStreamFlowControlWindow),
		protocol.ByteCount(s.config.MaxReceiveConnectionFlowControlWindow),
		s.config.IdleTimeout,
	)
	// zzh: initialize the datagram configuration
	if s.config.EnableDatagrams {
		s.MaxDatagramFrameSize = protocol.MaxDatagramFrameSize
		s.datagramQueue = newDatagramQueue(s, s.scheduleSending, s.logger)
		s.packetBuffer = NewPacketBuffer(s)
		s.sequenceID = 0
		s.nextIsStart = false
		s.currentBlockSize = 0
		s.currentBlockStartSequenceID = 0
	}

	s.scheduler = &scheduler{
		SchedulerName:     s.config.Scheduler,
		Training:          s.config.Training,
		AllowedCongestion: s.config.AllowedCongestion,
		DumpExp:           s.config.DumpExperiences,
	}
	s.scheduler.setup()

	if pconnMgr == nil && conn != nil {
		// XXX ONLY VALID FOR BENCHMARK!
		s.paths[protocol.InitialPathID] = &path{
			pathID: protocol.InitialPathID,
			sess:   s,
			conn:   conn,
		}
		s.paths[protocol.InitialPathID].setup(nil)
	} else if pconnMgr != nil && conn != nil {
		s.pathManager = &pathManager{pconnMgr: pconnMgr, sess: s}
		s.pathManager.setup(conn)
	} else {
		panic("session without conn")
	}
	// XXX (QDC): use the PathID 0 as the session RTT path
	s.rttStats = s.paths[protocol.InitialPathID].rttStats
	s.flowControlManager = flowcontrol.NewFlowControlManager(s.connectionParameters, s.rttStats, s.remoteRTTs)
	s.streamsMap = newStreamsMap(s.newStream, s.perspective, s.connectionParameters)
	s.streamFramer = newStreamFramer(s.streamsMap, s.flowControlManager)
	s.pathTimers = make(chan *path)

	var err error
	if s.perspective == protocol.PerspectiveServer {
		cryptoStream, _ := s.GetOrOpenStream(1)
		_, _ = s.AcceptStream() // don't expose the crypto stream
		verifySourceAddr := func(clientAddr net.Addr, cookie *Cookie) bool {
			return s.config.AcceptCookie(clientAddr, cookie)
		}
		if s.version.UsesTLS() {
			s.cryptoSetup, err = handshake.NewCryptoSetupTLS(
				"",
				s.perspective,
				s.version,
				tlsConf,
				cryptoStream,
				aeadChanged,
			)
		} else {
			s.cryptoSetup, err = newCryptoSetup(
				s.connectionID,
				s.paths[protocol.InitialPathID].conn.RemoteAddr(),
				s.version,
				scfg,
				cryptoStream,
				s.connectionParameters,
				s.config.Versions,
				verifySourceAddr,
				aeadChanged,
			)
		}
	} else {
		cryptoStream, _ := s.OpenStream()
		if s.version.UsesTLS() {
			s.cryptoSetup, err = handshake.NewCryptoSetupTLS(
				hostname,
				s.perspective,
				s.version,
				tlsConf,
				cryptoStream,
				aeadChanged,
			)
		} else {
			s.cryptoSetup, err = newCryptoSetupClient(
				hostname,
				s.connectionID,
				s.version,
				cryptoStream,
				tlsConf,
				s.connectionParameters,
				aeadChanged,
				&handshake.TransportParameters{RequestConnectionIDTruncation: s.config.RequestConnectionIDTruncation, CacheHandshake: s.config.CacheHandshake},
				negotiatedVersions,
			)
		}
	}
	if err != nil {
		return nil, nil, err
	}

	s.packer = newPacketPacker(s.connectionID,
		s.cryptoSetup,
		s.connectionParameters,
		s.streamFramer,
		// zzh: add the datagram queue in packet packer
		s.datagramQueue,
		s.perspective,
		s.version,
	)
	// zzh: add the datagram support
	s.unpacker = &packetUnpacker{aead: s.cryptoSetup, version: s.version, supportsDatagrams: s.config.EnableDatagrams}

	return s, handshakeChan, nil
}

// run the session main loop
func (s *session) run() error {
	// Start the crypto stream handler
	go func() {
		if err := s.cryptoSetup.HandleCryptoStream(); err != nil {
			s.Close(err)
		}
	}()

	var closeErr closeError
	aeadChanged := s.aeadChanged

	var timerPth *path

runLoop:
	for {
		// Close immediately if requested
		select {
		case closeErr = <-s.closeChan:
			s.pathsLock.RLock()
			for _, pth := range s.paths {
				select {
				case pth.closeChan <- nil:
				default:
				}
			}
			s.pathsLock.RUnlock()
			break runLoop
		default:
		}

		s.maybeResetTimer()

		select {
		case closeErr = <-s.closeChan:
			// We stop running the path manager, which will close paths
			if s.pathManager != nil {
				// XXX (QDC): for tests
				s.pathManager.closePaths()
				s.pathManager.runClosed <- struct{}{}
			}
			break runLoop
		case <-s.timer.Chan():
			s.timer.SetRead()
			// We do all the interesting stuff after the switch statement, so
			// nothing to see here.
		case <-s.sendingScheduled:
			// We do all the interesting stuff after the switch statement, so
			// nothing to see here.
		case tmpPth := <-s.pathTimers:
			timerPth = tmpPth
			// We do all the interesting stuff after the switch statement, so
			// nothing to see here.
		case p := <-s.receivedPackets:
			err := s.handlePacketImpl(p)
			if err != nil {
				if qErr, ok := err.(*qerr.QuicError); ok && qErr.ErrorCode == qerr.DecryptionFailure {
					s.tryQueueingUndecryptablePacket(p)
					continue
				}
				s.closeLocal(err)
				continue
			}
			// This is a bit unclean, but works properly, since the packet always
			// begins with the public header and we never copy it.
			putPacketBuffer(p.publicHeader.Raw)
		case l, ok := <-aeadChanged:
			if !ok { // the aeadChanged chan was closed. This means that the handshake is completed.
				s.handshakeComplete = true
				aeadChanged = nil // prevent this case from ever being selected again
				close(s.handshakeChan)
				close(s.handshakeCompleteChan)
			} else {
				s.tryDecryptingQueuedPackets()
				s.handshakeChan <- handshakeEvent{encLevel: l}
			}
		}

		now := time.Now()
		if timerPth != nil {
			if timeout := timerPth.sentPacketHandler.GetAlarmTimeout(); !timeout.IsZero() && timeout.Before(now) {
				// This could cause packets to be retransmitted, so check it before trying
				// to send packets.
				timerPth.sentPacketHandler.OnAlarm()
			}
			timerPth = nil
		}

		if !s.pathManagerLaunched && s.handshakeComplete {
			// XXX (QDC): for benchmark tests
			if s.pathManager != nil {
				s.pathManager.handshakeCompleted <- struct{}{}
				s.pathManagerLaunched = true
			}
		}

		if s.config.KeepAlive && s.handshakeComplete && time.Since(s.lastNetworkActivityTime) >= s.idleTimeout()/2 {
			// send the PING frame since there is no activity in the session
			s.pathsLock.RLock()
			// XXX (QDC): send PING over all paths, but is it really needed/useful?
			for _, tmpPth := range s.paths {
				s.packer.QueueControlFrame(&wire.PingFrame{}, tmpPth)
			}
			s.pathsLock.RUnlock()
			s.keepAlivePingSent = true
		}

		if err := s.sendPacket(); err != nil {
			s.closeLocal(err)
		}
		if !s.receivedTooManyUndecrytablePacketsTime.IsZero() && s.receivedTooManyUndecrytablePacketsTime.Add(protocol.PublicResetTimeout).Before(now) && len(s.undecryptablePackets) != 0 {
			s.closeLocal(qerr.Error(qerr.DecryptionFailure, "too many undecryptable packets received"))
		}
		if !s.handshakeComplete && now.Sub(s.sessionCreationTime) >= s.config.HandshakeTimeout {
			s.closeLocal(qerr.Error(qerr.HandshakeTimeout, "Crypto handshake did not complete in time."))
		}
		if s.handshakeComplete && now.Sub(s.lastNetworkActivityTime) >= s.idleTimeout() {
			s.closeLocal(qerr.Error(qerr.NetworkIdleTimeout, "No recent network activity."))
		}

		// Check if we should send a PATHS frame (currently hardcoded at 200 ms) only when at least one stream is open (not counting streams 1 and 3 never closed...)
		if s.handshakeComplete && s.version >= protocol.VersionMP && now.Sub(s.lastPathsFrameSent) >= 200*time.Millisecond && len(s.streamsMap.openStreams) > 2 {
			s.schedulePathsFrame()
		}

		s.garbageCollectStreams()
	}

	// only send the error the handshakeChan when the handshake is not completed yet
	// otherwise this chan will already be closed
	if !s.handshakeComplete {
		s.handshakeCompleteChan <- closeErr.err
		s.handshakeChan <- handshakeEvent{err: closeErr.err}
	}
	s.handleCloseError(closeErr)
	defer s.ctxCancel()
	return closeErr.err
}

func (s *session) Context() context.Context {
	return s.ctx
}

func (s *session) maybeResetTimer() {
	var deadline time.Time
	if s.config.KeepAlive && s.handshakeComplete && !s.keepAlivePingSent {
		deadline = s.lastNetworkActivityTime.Add(s.idleTimeout() / 2)
	} else {
		deadline = s.lastNetworkActivityTime.Add(s.idleTimeout())
	}

	if !s.handshakeComplete {
		handshakeDeadline := s.sessionCreationTime.Add(s.config.HandshakeTimeout)
		deadline = utils.MinTime(deadline, handshakeDeadline)
	}
	if !s.receivedTooManyUndecrytablePacketsTime.IsZero() {
		deadline = utils.MinTime(deadline, s.receivedTooManyUndecrytablePacketsTime.Add(protocol.PublicResetTimeout))
	}

	s.timer.Reset(deadline)
}

func (s *session) idleTimeout() time.Duration {
	return s.connectionParameters.GetIdleConnectionStateLifetime()
}

func (s *session) handlePacketImpl(p *receivedPacket) error {
	if s.perspective == protocol.PerspectiveClient {
		diversificationNonce := p.publicHeader.DiversificationNonce
		if len(diversificationNonce) > 0 {
			s.cryptoSetup.SetDiversificationNonce(diversificationNonce)
		}
	}

	if p.rcvTime.IsZero() {
		// To simplify testing
		p.rcvTime = time.Now()
	}

	s.lastNetworkActivityTime = p.rcvTime
	/// XXX (QDC): see if this should be brought at path level too
	s.keepAlivePingSent = false

	var pth *path
	var ok bool
	var err error

	pth, ok = s.paths[p.publicHeader.PathID]
	if !ok {
		// It's a new path initiated from remote host
		pth, err = s.pathManager.createPathFromRemote(p)
		if err != nil {
			return err
		}
	}
	return pth.handlePacketImpl(p)
}

func (s *session) handleFrames(fs []wire.Frame, p *path) error {
	for _, ff := range fs {
		var err error
		wire.LogFrame(ff, false)
		switch frame := ff.(type) {
		case *wire.StreamFrame:
			err = s.handleStreamFrame(frame)
		case *wire.AckFrame:
			err = s.handleAckFrame(frame)
		case *wire.ConnectionCloseFrame:
			s.closeRemote(qerr.Error(frame.ErrorCode, frame.ReasonPhrase))
		case *wire.GoawayFrame:
			err = errors.New("unimplemented: handling GOAWAY frames")
		case *wire.StopWaitingFrame:
			// LeastUnacked is guaranteed to have LeastUnacked > 0
			// therefore this will never underflow
			p.receivedPacketHandler.SetLowerLimit(frame.LeastUnacked - 1)
		case *wire.RstStreamFrame:
			err = s.handleRstStreamFrame(frame)
		case *wire.WindowUpdateFrame:
			err = s.handleWindowUpdateFrame(frame)
		case *wire.BlockedFrame:
			s.peerBlocked = true
		case *wire.PingFrame:
		case *wire.AddAddressFrame:
			if s.pathManager != nil {
				err = s.pathManager.handleAddAddressFrame(frame)
				s.schedulePathsFrame()
			}
			// zzh: handle the datagram frame
		case *wire.DatagramFrame:
			err = s.handleDatagramFrame(frame)
		case *wire.ClosePathFrame:
			s.handleClosePathFrame(frame)
		case *wire.PathsFrame:
			// So far, do nothing
			s.pathsLock.RLock()
			for i := 0; i < int(frame.NumPaths); i++ {
				s.remoteRTTs[frame.PathIDs[i]] = frame.RemoteRTTs[i]
				if frame.RemoteRTTs[i] >= 30*time.Minute {
					// Path is potentially failed
					s.paths[frame.PathIDs[i]].potentiallyFailed.Set(true)
				}
			}
			s.pathsLock.RUnlock()
		default:
			return errors.New("Session BUG: unexpected frame type")
		}

		if err != nil {
			switch err {
			case ackhandler.ErrDuplicateOrOutOfOrderAck:
				// Can happen e.g. when packets thought missing arrive late
			case errRstStreamOnInvalidStream:
				// Can happen when RST_STREAMs arrive early or late (?)
				utils.Errorf("Ignoring error in session: %s", err.Error())
			case errWindowUpdateOnClosedStream:
				// Can happen when we already sent the last StreamFrame with the FinBit, but the client already sent a WindowUpdate for this Stream
			default:
				return err
			}
		}
	}
	return nil
}

// handlePacket is called by the server with a new packet
func (s *session) handlePacket(p *receivedPacket) {
	// Discard packets once the amount of queued packets is larger than
	// the channel size, protocol.MaxSessionUnprocessedPackets
	// XXX (QDC): Multipath still rely on one buffer for the connection;
	// in the future, it might make more sense to first buffer in the
	// path and then give it to the connection...
	select {
	case s.receivedPackets <- p:
	default:
	}
}

func (s *session) handleStreamFrame(frame *wire.StreamFrame) error {
	str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		// Stream is closed and already garbage collected
		// ignore this StreamFrame
		return nil
	}
	if frame.FinBit {
		// Receiving end of stream, print stats about it
		// Print client statistics about its paths
		s.pathsLock.RLock()
		utils.Infof("Info for stream %x of %x", frame.StreamID, s.connectionID)
		for pathID, pth := range s.paths {
			sntPkts, sntRetrans, sntLost := pth.sentPacketHandler.GetStatistics()
			rcvPkts := pth.receivedPacketHandler.GetStatistics()
			utils.Infof("Path %x: sent %d retrans %d lost %d; rcv %d", pathID, sntPkts, sntRetrans, sntLost, rcvPkts)
		}
		s.pathsLock.RUnlock()
	}
	return str.AddStreamFrame(frame)
}

func (s *session) handleWindowUpdateFrame(frame *wire.WindowUpdateFrame) error {
	if frame.StreamID != 0 {
		str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
		if err != nil {
			return err
		}
		if str == nil {
			return errWindowUpdateOnClosedStream
		}
	}
	_, err := s.flowControlManager.UpdateWindow(frame.StreamID, frame.ByteOffset)
	return err
}

func (s *session) handleRstStreamFrame(frame *wire.RstStreamFrame) error {
	str, err := s.streamsMap.GetOrOpenStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		return errRstStreamOnInvalidStream
	}

	str.RegisterRemoteError(fmt.Errorf("RST_STREAM received with code %d", frame.ErrorCode))
	return s.flowControlManager.ResetStream(frame.StreamID, frame.ByteOffset)
}

func (s *session) handleAckFrame(frame *wire.AckFrame) error {
	pth := s.paths[frame.PathID]
	ackedPackets, err := pth.sentPacketHandler.ReceivedAck(frame, pth.lastRcvdPacketNumber, pth.lastNetworkActivityTime)
	if ackedPackets == nil {
		fmt.Println("No acked packets")
	}

	// 如果数据包中包含 DatagramFrame，更新 PacketInfo 的 Processed 字段
	for _, packetElement := range ackedPackets {
		//fmt.Println("Received ACK for DatagramFrame")
		if packetElement == nil {
			//fmt.Println("packetElement is nil")
			break
		}
		for _, frame := range packetElement.Value.GetFramesForACK() {
			switch f := frame.(type) {
			case *wire.DatagramFrame:
				fmt.Println("Received ACK for DatagramFrame 2")
				packetInfo, erro := s.packetBuffer.GetPacketInfoByFrame(f)
				fmt.Println("Received ACK for DatagramFrame 3")
				if erro == nil {
					packetInfo.Processed = true
					s.packetBuffer.Refreshinfonolog(f, packetInfo)
					fmt.Printf("Received ACK for DatagramFrame with SequenceID: %d\n", packetInfo.BlockSequenceID)
				}
			default:
				continue
			}
		}
	}

	fmt.Println("Received ACK for DatagramFrame after loop")
	if err == nil && pth.rttStats.SmoothedRTT() > s.rttStats.SmoothedRTT() {
		// Update the session RTT, which comes to take the max RTT on all paths
		s.rttStats.UpdateSessionRTT(pth.rttStats.SmoothedRTT())
	}
	return err
}

func (s *session) handleClosePathFrame(frame *wire.ClosePathFrame) error {
	if err := s.closePath(frame.PathID, false); err != nil {
		return err
	}
	// This is safe because closePath checks this
	pth := s.paths[frame.PathID]
	// This allows the host to retransmit packets sent on this path that were not acked by the ClosePath frame
	return pth.sentPacketHandler.ReceivedClosePath(frame, pth.lastRcvdPacketNumber, pth.lastNetworkActivityTime)
}

// zzh: add the handle datagram frame
func (s *session) handleDatagramFrame(f *wire.DatagramFrame) error {
	length, _ := f.MinLength(s.version)
	if length > protocol.MaxDatagramFrameSize {
		return errors.New("DATAGRAM frame too large")
	}
	s.datagramQueue.HandleDatagramFrame(f)
	return nil
}

func (s *session) closePath(pthID protocol.PathID, sendClosePathFrame bool) error {
	s.pathsLock.RLock()
	defer s.pathsLock.RUnlock()

	pth, ok := s.paths[pthID]
	if !ok {
		return errors.New("Unknown path ID to close")
	}

	_, ok = s.closedPaths[pthID]
	if ok {
		// XXX (QDC) Path already closed, should we raise an error?
		return nil
	}

	if s.pathManager != nil {
		s.pathManager.closePath(pthID)
	}

	s.closedPaths[pthID] = true

	if !sendClosePathFrame {
		return nil
	}

	pth.sentPacketHandler.SetInflightAsLost()
	closePathFrame := pth.GetClosePathFrame()
	s.streamFramer.AddClosePathFrameForTransmission(closePathFrame)

	return nil
}

func (s *session) schedulePathsFrame() {
	s.lastPathsFrameSent = time.Now()
	s.streamFramer.AddPathsFrameForTransmission(s)
}

func (s *session) closePaths() {
	// XXX (QDC): still for tests
	if s.pathManager != nil {
		s.pathManager.closePaths()
		if s.pathManager.pconnMgr == nil {
			// XXX For tests
			s.paths[0].conn.Close()
		}
	} else {
		s.pathsLock.RLock()
		for _, pth := range s.paths {
			select {
			case pth.closeChan <- nil:
			default:
				// Don't block
			}
		}
		s.pathsLock.RUnlock()
	}

	// wait for the run loops of path to finish
	for _, pth := range s.paths {
		<-pth.runClosed
	}
}

func (s *session) closeLocal(e error) {
	s.closeOnce.Do(func() {
		s.closeChan <- closeError{err: e, remote: false}
	})
}

func (s *session) closeRemote(e error) {
	s.closeOnce.Do(func() {
		s.closeChan <- closeError{err: e, remote: true}
	})
}

// Close the connection. If err is nil it will be set to qerr.PeerGoingAway.
// It waits until the run loop has stopped before returning
func (s *session) Close(e error) error {
	s.closeLocal(e)
	<-s.ctx.Done()
	return nil
}

func (s *session) handleCloseError(closeErr closeError) error {
	if closeErr.err == nil {
		closeErr.err = qerr.PeerGoingAway
	}

	var quicErr *qerr.QuicError
	var ok bool
	if quicErr, ok = closeErr.err.(*qerr.QuicError); !ok {
		quicErr = qerr.ToQuicError(closeErr.err)
	}
	// Don't log 'normal' reasons
	if quicErr.ErrorCode == qerr.PeerGoingAway || quicErr.ErrorCode == qerr.NetworkIdleTimeout {
		utils.Infof("Closing connection %x", s.connectionID)
	} else {
		utils.Errorf("Closing session with error: %s", closeErr.err.Error())
	}

	s.streamsMap.CloseWithError(quicErr)

	// zzh: add the datagram queue close error
	if s.datagramQueue != nil {
		s.datagramQueue.CloseWithError(quicErr)
	}

	if closeErr.err == errCloseSessionForNewVersion {
		return nil
	}

	s.closePaths()

	// If this is a remote close we're done here
	if closeErr.remote {
		return nil
	}

	if quicErr.ErrorCode == qerr.DecryptionFailure ||
		quicErr == handshake.ErrHOLExperiment ||
		quicErr == handshake.ErrNSTPExperiment {
		// XXX seems reasonable to send public reset on path ID 0, but this can change
		return s.sendPublicReset(s.paths[0].lastRcvdPacketNumber)
	}
	return s.sendConnectionClose(quicErr)
}

func (s *session) sendPacket() error {
	return s.scheduler.sendPacket(s)
}

func (s *session) sendPackedPacket(packet *packedPacket, pth *path) error {
	defer putPacketBuffer(packet.raw)
	err := pth.sentPacketHandler.SentPacket(&ackhandler.Packet{
		PacketNumber:    packet.number,
		Frames:          packet.frames,
		Length:          protocol.ByteCount(len(packet.raw)),
		EncryptionLevel: packet.encryptionLevel,
	})
	if err != nil {
		return err
	}
	pth.sentPacket <- struct{}{}

	s.logPacket(packet, pth.pathID)
	return pth.conn.Write(packet.raw)
}

func (s *session) sendConnectionClose(quicErr *qerr.QuicError) error {
	s.paths[0].SetLeastUnacked(s.paths[0].sentPacketHandler.GetLeastUnacked())
	packet, err := s.packer.PackConnectionClose(&wire.ConnectionCloseFrame{
		ErrorCode:    quicErr.ErrorCode,
		ReasonPhrase: quicErr.ErrorMessage,
	}, s.paths[0])
	if err != nil {
		return err
	}
	s.logPacket(packet, protocol.InitialPathID)
	// XXX (QDC): seems reasonable to send on pathID 0, but this can change
	return s.paths[protocol.InitialPathID].conn.Write(packet.raw)
}

func (s *session) sendPing(pth *path) error {
	packet, err := s.packer.PackPing(&wire.PingFrame{}, pth)
	if err != nil {
		return err
	}
	if packet == nil {
		return errors.New("Session BUG: expected ping packet not to be nil")
	}
	return s.sendPackedPacket(packet, pth)
}

func (s *session) logPacket(packet *packedPacket, pathID protocol.PathID) {
	if !utils.Debug() {
		// We don't need to allocate the slices for calling the format functions
		return
	}
	utils.Debugf("Time: %d", time.Since(s.sessionCreationTime).Nanoseconds()/1000000)
	utils.Debugf("Path: %d, Cong: %d", pathID, s.paths[pathID].sentPacketHandler.GetCongestionWindow())
	utils.Debugf("Path: %d, BytesInFlight: %d", pathID, s.paths[pathID].sentPacketHandler.GetBytesInFlight())
	utils.Debugf("-> Sending packet 0x%x (%d bytes) for connection %x on path %x, %s", packet.number, len(packet.raw), s.connectionID, pathID, packet.encryptionLevel)
	for _, frame := range packet.frames {
		wire.LogFrame(frame, true)
	}
}

// GetOrOpenStream either returns an existing stream, a newly opened stream, or nil if a stream with the provided ID is already closed.
// Newly opened streams should only originate from the client. To open a stream from the server, OpenStream should be used.
func (s *session) GetOrOpenStream(id protocol.StreamID) (Stream, error) {
	str, err := s.streamsMap.GetOrOpenStream(id)
	if str != nil {
		return str, err
	}
	// make sure to return an actual nil value here, not an Stream with value nil
	return nil, err
}

// AcceptStream returns the next stream openend by the peer
func (s *session) AcceptStream() (Stream, error) {
	return s.streamsMap.AcceptStream()
}

// OpenStream opens a stream
func (s *session) OpenStream() (Stream, error) {
	return s.streamsMap.OpenStream()
}

func (s *session) OpenStreamSync() (Stream, error) {
	return s.streamsMap.OpenStreamSync()
}

func (s *session) WaitUntilHandshakeComplete() error {
	return <-s.handshakeCompleteChan
}

func (s *session) queueResetStreamFrame(id protocol.StreamID, offset protocol.ByteCount) {
	s.packer.QueueControlFrame(&wire.RstStreamFrame{
		StreamID:   id,
		ByteOffset: offset,
	}, s.paths[protocol.InitialPathID])
	s.scheduleSending()
}

func (s *session) newStream(id protocol.StreamID) *stream {
	// TODO: find a better solution for determining which streams contribute to connection level flow control
	if id == 1 || id == 3 {
		s.flowControlManager.NewStream(id, false)
	} else {
		s.flowControlManager.NewStream(id, true)
	}
	return newStream(id, s.scheduleSending, s.queueResetStreamFrame, s.flowControlManager)
}

// garbageCollectStreams goes through all streams and removes EOF'ed streams
// from the streams map.
func (s *session) garbageCollectStreams() {
	s.streamsMap.Iterate(func(str *stream) (bool, error) {
		id := str.StreamID()
		if str.finished() {
			err := s.streamsMap.RemoveStream(id)
			if err != nil {
				return false, err
			}
			s.flowControlManager.RemoveStream(id)
		}
		return true, nil
	})
}

func (s *session) sendPublicReset(rejectedPacketNumber protocol.PacketNumber) error {
	utils.Infof("Sending public reset for connection %x, packet number %d", s.connectionID, rejectedPacketNumber)
	// XXX: seems reasonable to send on the pathID 0, but this can change
	return s.paths[protocol.InitialPathID].conn.Write(wire.WritePublicReset(s.connectionID, rejectedPacketNumber, 0))
}

// scheduleSending signals that we have data for sending
func (s *session) scheduleSending() {
	select {
	case s.sendingScheduled <- struct{}{}:
	default:
	}
}

func (s *session) tryQueueingUndecryptablePacket(p *receivedPacket) {
	if s.handshakeComplete {
		utils.Debugf("Received undecryptable packet from %s after the handshake: %#v, %d bytes data", p.remoteAddr.String(), p.publicHeader, len(p.data))
		return
	}
	if len(s.undecryptablePackets)+1 > protocol.MaxUndecryptablePackets {
		// if this is the first time the undecryptablePackets runs full, start the timer to send a Public Reset
		if s.receivedTooManyUndecrytablePacketsTime.IsZero() {
			s.receivedTooManyUndecrytablePacketsTime = time.Now()
			s.maybeResetTimer()
		}
		utils.Infof("Dropping undecrytable packet 0x%x (undecryptable packet queue full)", p.publicHeader.PacketNumber)
		return
	}
	utils.Infof("Queueing packet 0x%x for later decryption", p.publicHeader.PacketNumber)
	s.undecryptablePackets = append(s.undecryptablePackets, p)
}

func (s *session) tryDecryptingQueuedPackets() {
	for _, p := range s.undecryptablePackets {
		s.handlePacket(p)
	}
	s.undecryptablePackets = s.undecryptablePackets[:0]
}

func (s *session) getWindowUpdateFrames(force bool) []*wire.WindowUpdateFrame {
	updates := s.flowControlManager.GetWindowUpdates(force)
	res := make([]*wire.WindowUpdateFrame, len(updates))
	for i, u := range updates {
		res[i] = &wire.WindowUpdateFrame{StreamID: u.StreamID, ByteOffset: u.Offset}
	}
	return res
}

func (s *session) LocalAddr() net.Addr {
	// XXX (QDC): do it like with MPTCP (master initial path), what if it is closed?
	return s.paths[0].conn.LocalAddr()
}

// RemoteAddr returns the net.Addr of the client
func (s *session) RemoteAddr() net.Addr {
	// XXX (QDC): do it like with MPTCP (master initial path), what if it is closed?
	return s.paths[0].conn.RemoteAddr()
}

func (s *session) GetVersion() protocol.VersionNumber {
	return s.version
}

func (s *session) Getdeadlinestatus() time.Duration {
	if s.config.Scheduler != "arrive_time" {
		return 0
	}

	arriveTime, ok := s.scheduler.calculateArrivalTimefromsendbuffer(s, s.scheduler.pthtoarrive, false)
	if ok {
		return arriveTime
	} else {
		return 0
	}
}

// zzh: datagram interface
func (s *session) SendMessage(p []byte) error {
	// 检查是否是块结束标记
	if string(p) == "BLOCK_END" {
		fmt.Printf("Block end marker detected \n")
		if s.sequenceID > 0 {
			lastSequenceID := s.sequenceID - 1
			if frame, info, err := s.packetBuffer.GetPacket(lastSequenceID); err == nil {
				info.IsEnd = true
				info.BlockSize = s.currentBlockSize
				info.BlockSequenceID = s.currentBlockStartSequenceID
				s.packetBuffer.AddPacket(frame, info)
			}
		}
		// 重置块大小和起始序号
		s.currentBlockSize = 0
		// s.currentBlockStartSequenceID = s.sequenceID
		// 设置下一个数据包为开头
		s.nextIsStart = true
		// 跳过块结束标记，继续读取下一个数据包
		return nil
	}

	// 创建 PacketInfo
	packetInfo := PacketInfo{
		IsStart:         s.sequenceID == 0 || s.nextIsStart, // 序列号为0的数据包为开头
		IsEnd:           false,
		SequenceID:      s.sequenceID,
		Processed:       false,
		BlockSize:       0,
		Packetsize:      len(p),
		BlockSequenceID: s.currentBlockStartSequenceID,
	}

	// 重置 nextIsStart 标记
	// 如果是块的开头，递增序列号并记录起始序号
	if s.nextIsStart {
		s.currentBlockStartSequenceID++
		s.nextIsStart = false
		packetInfo.BlockSequenceID = s.currentBlockStartSequenceID
	}

	f := &wire.DatagramFrame{DataLenPresent: true}
	// fmt.Println("datagram frame size: ", f.MaxDataLen(s.MaxDatagramFrameSize, s.version))
	// fmt.Println("datagram frame size: ", protocol.ByteCount(len(p)))
	if protocol.ByteCount(len(p)) > f.MaxDataLen(s.MaxDatagramFrameSize, s.version) {
		return errors.New("message too large")
	}
	f.Data = make([]byte, len(p))
	copy(f.Data, p)

	// 添加数据包到 PacketBuffer
	s.packetBuffer.AddPacket(f, packetInfo)

	s.datagramQueue.AddAndWait(f)

	// 更新当前块的大小
	s.currentBlockSize += len(p)

	// 递增序列ID
	s.sequenceID++

	return nil
}

func (s *session) ReceiveMessage() ([]byte, error) {
	return s.datagramQueue.Receive()
}
