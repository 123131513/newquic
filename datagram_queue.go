package quic

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/123131513/newquic/internal/protocol"
	"github.com/123131513/newquic/internal/utils"
	"github.com/123131513/newquic/internal/wire"
)

type datagramQueue struct {
	sendQueue chan *wire.DatagramFrame
	rcvQueue  chan []byte

	closeErr error
	closed   chan struct{}

	hasData func()

	dequeued chan struct{}

	logger utils.Logger
	// zzh: add retransmissionQueue
	retransmissionQueue    chan *wire.DatagramFrame
	retransmissionDequeued chan struct{}
	packetBuffer           *PacketBuffer
	mu                     sync.Mutex // Add a mutex for protecting hasData

	// zzh:用于存储已接收的数据的哈希值
	receivedDataHashes map[string]struct{}
}

func newDatagramQueue(s *session, hasData func(), logger utils.Logger) *datagramQueue {
	return &datagramQueue{
		hasData:                hasData,
		sendQueue:              make(chan *wire.DatagramFrame, 1),
		rcvQueue:               make(chan []byte, protocol.DatagramRcvQueueLen),
		dequeued:               make(chan struct{}),
		closed:                 make(chan struct{}),
		logger:                 logger,
		retransmissionQueue:    make(chan *wire.DatagramFrame, 1),
		retransmissionDequeued: make(chan struct{}),
		packetBuffer:           NewPacketBuffer(s),
		receivedDataHashes:     make(map[string]struct{}), // 初始化哈希值集合
	}
}

// AddAndWait queues a new DATAGRAM frame for sending.
// It blocks until the frame has been dequeued.
func (h *datagramQueue) AddAndWait(f *wire.DatagramFrame) error {
	select {
	case h.sendQueue <- f:
		// h.mu.Lock()
		h.hasData()
	case <-h.closed:
		// h.mu.Unlock()
		return h.closeErr
	}

	select {
	case <-h.dequeued:
		// h.mu.Unlock()
		return nil
	case <-h.closed:
		// h.mu.Unlock()
		return h.closeErr
	}
}

// zzh: AddToRetransmissionQueue adds a DATAGRAM frame to the retransmission queue.
// AddToRetransmissionQueue adds a DATAGRAM frame to the retransmission queue.
func (h *datagramQueue) AddToRetransmissionQueue(f *wire.DatagramFrame) error {
	// 设置超时逻辑
	timeout1 := 1 * time.Millisecond // 超时设置，可以根据需求调整
	fmt.Println("AddToRetransmissionQueue before")
	select {
	case h.retransmissionQueue <- f:
		fmt.Println("AddToRetransmissionQueue before 2")
		// h.mu.Lock()
		fmt.Println("AddToRetransmissionQueue")
		h.hasData()
	case <-time.After(timeout1): // 超时处理
		fmt.Println("AddToRetransmissionQueue timed out, clearing retransmissionQueue")

		// 清空 retransmissionQueue
		for len(h.retransmissionQueue) > 0 {
			select {
			case <-h.retransmissionQueue: // 清空队列中的数据
				fmt.Println("Cleared a frame from retransmissionQueue due to timeout")
			default:
				break // 如果队列已空，则退出循环
			}
		}
		// h.mu.Unlock()
		return nil
	case <-h.closed:
		// h.mu.Unlock()
		return h.closeErr
	}
	// 设置超时逻辑
	timeout2 := 1 * time.Millisecond // 超时设置，可以根据需求调整
	fmt.Println("AddToRetransmissionQueue  2")
	select {
	case <-h.retransmissionDequeued:
		// h.mu.Unlock()
		fmt.Println("AddToRetransmissionQueue  3")
		return nil
	case <-time.After(timeout2): // 超时处理
		fmt.Println("AddToRetransmissionQueue timed out, clearing retransmissionQueue")

		// 清空 retransmissionQueue
		for len(h.retransmissionQueue) > 0 {
			select {
			case <-h.retransmissionQueue: // 清空队列中的数据
				fmt.Println("Cleared a frame from retransmissionQueue due to timeout")
			default:
				break // 如果队列已空，则退出循环
			}
		}
		// h.mu.Unlock()
		return nil
	case <-h.closed:
		// h.mu.Unlock()
		return h.closeErr
	}
}

// Get dequeues a DATAGRAM frame for sending.
func (h *datagramQueue) Get() *wire.DatagramFrame {
	select {
	case f := <-h.retransmissionQueue:
		h.retransmissionDequeued <- struct{}{}
		return f
	case f := <-h.sendQueue:
		h.dequeued <- struct{}{}
		return f
	default:
		return nil
	}
}

// HandleDatagramFrame handles a received DATAGRAM frame.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	// zzh:重复数据报避免
	// 计算数据的哈希值
	dataHash := hashData(f.Data)

	h.mu.Lock()
	defer h.mu.Unlock()

	// 检查该数据的哈希值是否已存在于已接收的哈希集合中
	if _, exists := h.receivedDataHashes[dataHash]; exists {
		// 如果已经接收过该数据，忽略该数据帧
		fmt.Printf("Duplicate frame detected with data hash: %x, ignoring\n", dataHash)
		return
	}

	// 如果是新的帧，处理并加入到历史记录
	fmt.Printf("Handling new frame with data hash: %x\n", dataHash)

	// 将该数据的哈希值加入到历史记录中
	h.receivedDataHashes[dataHash] = struct{}{}

	// 将数据帧复制到接收队列
	data := make([]byte, len(f.Data))
	copy(data, f.Data)
	select {
	case h.rcvQueue <- data:
	default:
		h.logger.Debugf("Discarding DATAGRAM frame (%d bytes payload)", len(f.Data))
	}
}

// Receive gets a received DATAGRAM frame.
func (h *datagramQueue) Receive() ([]byte, error) {
	select {
	case data := <-h.rcvQueue:
		return data, nil
	case <-h.closed:
		return nil, h.closeErr
	}
}

func (h *datagramQueue) CloseWithError(e error) {
	h.closeErr = e
	close(h.closed)
}

// zzh:计算数据的哈希值，避免重复
func hashData(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash) // 返回十六进制的哈希字符串
}
