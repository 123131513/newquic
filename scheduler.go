package quic

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"time"

	"github.com/Workiva/go-datastructures/queue"

	"gonum.org/v1/gonum/mat"

	"github.com/123131513/newquic/ackhandler"
	"github.com/123131513/newquic/congestion"
	"github.com/123131513/newquic/constants"
	"github.com/123131513/newquic/internal/protocol"
	"github.com/123131513/newquic/internal/utils"
	"github.com/123131513/newquic/internal/wire"
	"github.com/123131513/newquic/util"
)

const banditAlpha = 0.75
const banditDimension = 6

// zzh: add deadline for packet
const deadline = 300 * time.Millisecond

// zzh: begin from ytxing's code
// PacketList zzh
type PacketList struct {
	queue    []*packedFrames //zzh: some frames are supposed to be a packet but not sealed.
	len      int             // zzh: how many packet
	toPathid protocol.PathID
}

type packedFrames struct {
	frames    []wire.Frame //zzh: a slice of a slice of frames.
	queueTime time.Time
}

// GetPathSmoothedRTT get smoothed RTT in time.Duration
// zzh
func GetPathSmoothedRTT(pth *path) time.Duration {
	return pth.rttStats.SmoothedRTT()

}

type scheduler struct {
	// XXX Currently round-robin based, inspired from MPTCP scheduler
	quotas map[protocol.PathID]uint
	// Selected scheduler
	SchedulerName string
	// Is training?
	Training bool

	// Cached state for training
	cachedPathID protocol.PathID

	AllowedCongestion int

	// async updated reward
	record        uint64
	episoderecord uint64
	packetvector  [6000]uint64
	actionvector  [6000]int
	lastfiretime  time.Time
	zz            [6000]time.Time
	waiting       uint64

	// linUCB
	fe           uint64
	se           uint64
	MAaF         [banditDimension][banditDimension]float64
	MAaS         [banditDimension][banditDimension]float64
	MbaF         [banditDimension]float64
	MbaS         [banditDimension]float64
	featureone   [6000]float64
	featuretwo   [6000]float64
	featurethree [6000]float64
	featurefour  [6000]float64
	featurefive  [6000]float64
	featuresix   [6000]float64
	// Retrans cache
	retrans map[protocol.PathID]uint64

	// Write experiences
	DumpExp   bool
	DumpPath  string
	dumpAgent experienceAgent

	// Project Home Directory
	projectHomeDir string

	// pathID Queue for Round Robin
	pathQueue queue.Queue

	// zzh: add buffer for packets
	packetsNotSentYet map[protocol.PathID]*PacketList       //zzh
	previousPath      map[protocol.StreamID]protocol.PathID //zzh: used to calculate arrival time
	previoussendtime  time.Duration                         //zzh: used to calculate arrival time
	pthtoarrive       *path
}

type queuePathIdItem struct {
	pathId protocol.PathID
	path   *path
}

func (sch *scheduler) setup() {
	sch.projectHomeDir = os.Getenv(constants.PROJECT_HOME_DIR)
	if sch.projectHomeDir == "" {
		panic("`PROJECT_HOME_DIR` Env variable was not provided, this is needed for training")
	}
	sch.quotas = make(map[protocol.PathID]uint)
	sch.retrans = make(map[protocol.PathID]uint64)
	sch.waiting = 0

	//Read lin to buffer
	linFileName := sch.projectHomeDir + "/sch_out/lin"
	file, err := os.OpenFile(linFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	for i := 0; i < banditDimension; i++ {
		for j := 0; j < banditDimension; j++ {
			fmt.Fscanln(file, &sch.MAaF[i][j])
		}
	}
	for i := 0; i < banditDimension; i++ {
		for j := 0; j < banditDimension; j++ {
			fmt.Fscanln(file, &sch.MAaS[i][j])
		}
	}
	for i := 0; i < banditDimension; i++ {
		fmt.Fscanln(file, &sch.MbaF[i])
	}
	for i := 0; i < banditDimension; i++ {
		fmt.Fscanln(file, &sch.MbaS[i])
	}
	file.Close()

	//TODO: expose to config
	sch.DumpPath = "/tmp/"
	sch.dumpAgent.Setup()

	// zzh: add buffer for packets
	sch.packetsNotSentYet = make(map[protocol.PathID]*PacketList)
	sch.previousPath = make(map[protocol.StreamID]protocol.PathID)
}

func (sch *scheduler) getRetransmission(s *session) (hasRetransmission bool, retransmitPacket *ackhandler.Packet, pth *path) {
	// check for retransmissions first
	for {
		// TODO add ability to reinject on another path
		// XXX We need to check on ALL paths if any packet should be first retransmitted
		s.pathsLock.RLock()
	retransmitLoop:
		for _, pthTmp := range s.paths {
			retransmitPacket = pthTmp.sentPacketHandler.DequeuePacketForRetransmission()
			if retransmitPacket != nil {
				pth = pthTmp
				break retransmitLoop
			}
		}
		s.pathsLock.RUnlock()
		if retransmitPacket == nil {
			break
		}
		hasRetransmission = true

		if retransmitPacket.EncryptionLevel != protocol.EncryptionForwardSecure {
			if s.handshakeComplete {
				// Don't retransmit handshake packets when the handshake is complete
				continue
			}
			utils.Debugf("\tDequeueing handshake retransmission for packet 0x%x", retransmitPacket.PacketNumber)
			return
		}
		utils.Debugf("\tDequeueing retransmission of packet 0x%x from path %d", retransmitPacket.PacketNumber, pth.pathID)
		// resend the frames that were in the packet
		for _, frame := range retransmitPacket.GetFramesForRetransmission() {
			switch f := frame.(type) {
			case *wire.StreamFrame:
				s.streamFramer.AddFrameForRetransmission(f)
			case *wire.WindowUpdateFrame:
				// only retransmit WindowUpdates if the stream is not yet closed and the we haven't sent another WindowUpdate with a higher ByteOffset for the stream
				// XXX Should it be adapted to multiple paths?
				currentOffset, err := s.flowControlManager.GetReceiveWindow(f.StreamID)
				if err == nil && f.ByteOffset >= currentOffset {
					s.packer.QueueControlFrame(f, pth)
				}
			case *wire.PathsFrame:
				// Schedule a new PATHS frame to send
				s.schedulePathsFrame()
			default:
				s.packer.QueueControlFrame(frame, pth)
			}
		}
	}
	return
}

func (sch *scheduler) selectPathRoundRobin(s *session, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) *path {
	if sch.quotas == nil {
		sch.setup()
	}

	// Log Path Id w/ Interface Name
	//for pathId, pth := range s.paths {
	//	fmt.Printf("Path Id: %d, Local Addr: %s, Remote Addr: %s \t", pathId, pth.conn.LocalAddr(), pth.conn.RemoteAddr())
	//}

	// XXX Avoid using PathID 0 if there is more than 1 path
	if len(s.paths) <= 1 {
		if !hasRetransmission && !s.paths[protocol.InitialPathID].SendingAllowed() {
			return nil
		}
		return s.paths[protocol.InitialPathID]
	}

	if sch.pathQueue.Empty() {
		for pathId, pth := range s.paths {
			err := sch.pathQueue.Put(queuePathIdItem{pathId: pathId, path: pth})
			if err != nil {
				fmt.Println("Err Inserting in Queue, Error: ", err.Error())
			}
		}
	} else if int64(len(s.paths)) != sch.pathQueue.Len() {
		sch.pathQueue.Get(sch.pathQueue.Len())
		for pathId, pth := range s.paths {
			err := sch.pathQueue.Put(queuePathIdItem{pathId: pathId, path: pth})
			if err != nil {
				fmt.Println("Err Inserting in Queue, Error: ", err.Error())
			}
		}
	}

pathLoop:
	for pathID, pth := range s.paths {
		pathIdFromQueue, _ := sch.pathQueue.Peek()
		pathIdObj, ok := pathIdFromQueue.(queuePathIdItem)
		if !ok {
			panic("Invalid Interface Type Chosen")
		}

		// Don't block path usage if we retransmit, even on another path
		// If this path is potentially failed, do no consider it for sending
		// XXX Prevent using initial pathID if multiple paths
		if (!hasRetransmission && !pth.SendingAllowed()) || pth.potentiallyFailed.Get() || pathID == protocol.InitialPathID {
			if pathIdObj.pathId == pathID {
				_, _ = sch.pathQueue.Get(1)
				_ = sch.pathQueue.Put(pathIdObj)
			}
			continue pathLoop
		}

		if pathIdObj.pathId == pathID {
			_, _ = sch.pathQueue.Get(1)
			_ = sch.pathQueue.Put(pathIdObj)
			return pth
		}
	}
	return nil

}

func (sch *scheduler) selectPathLowLatency(s *session, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) *path {
	// XXX Avoid using PathID 0 if there is more than 1 path
	utils.Debugf("selectPathLowLatency")
	if len(s.paths) <= 1 {
		if !hasRetransmission && !s.paths[protocol.InitialPathID].SendingAllowed() {
			utils.Debugf("Only initial path and sending not allowed without retransmission")
			utils.Debugf("SCH RTT - NIL")
			return nil
		}
		utils.Debugf("Only initial path and sending is allowed or has retransmission")
		utils.Debugf("SCH RTT - InitialPath")
		return s.paths[protocol.InitialPathID]
	}

	// FIXME Only works at the beginning... Cope with new paths during the connection
	if hasRetransmission && hasStreamRetransmission && fromPth.rttStats.SmoothedRTT() == 0 {
		// Is there any other path with a lower number of packet sent?
		currentQuota := sch.quotas[fromPth.pathID]
		for pathID, pth := range s.paths {
			if pathID == protocol.InitialPathID || pathID == fromPth.pathID {
				continue
			}
			// The congestion window was checked when duplicating the packet
			if sch.quotas[pathID] < currentQuota {
				return pth
			}
		}
	}

	var selectedPath *path
	var lowerRTT time.Duration
	var currentRTT time.Duration
	selectedPathID := protocol.PathID(255)

pathLoop:
	for pathID, pth := range s.paths {
		// Don't block path usage if we retransmit, even on another path
		if !hasRetransmission && !pth.SendingAllowed() {
			utils.Debugf("Discarding %d - no has ret and sending is not allowed ", pathID)
			continue pathLoop
		}

		// If this path is potentially failed, do not consider it for sending
		if pth.potentiallyFailed.Get() {
			utils.Debugf("Discarding %d - potentially failed", pathID)
			continue pathLoop
		}

		// XXX Prevent using initial pathID if multiple paths
		if pathID == protocol.InitialPathID {
			continue pathLoop
		}

		currentRTT = pth.rttStats.SmoothedRTT()

		// Prefer staying single-path if not blocked by current path
		// Don't consider this sample if the smoothed RTT is 0
		if lowerRTT != 0 && currentRTT == 0 {
			utils.Debugf("Discarding %d - currentRTT == 0 and lowerRTT != 0 ", pathID)
			continue pathLoop
		}

		// Case if we have multiple paths unprobed
		if currentRTT == 0 {
			currentQuota, ok := sch.quotas[pathID]
			if !ok {
				sch.quotas[pathID] = 0
				currentQuota = 0
			}
			lowerQuota, _ := sch.quotas[selectedPathID]
			if selectedPath != nil && currentQuota > lowerQuota {
				utils.Debugf("Discarding %d - higher quota ", pathID)
				continue pathLoop
			}
		}

		if currentRTT != 0 && lowerRTT != 0 && selectedPath != nil && currentRTT >= lowerRTT {
			utils.Debugf("Discarding %d - higher SRTT ", pathID)
			continue pathLoop
		}

		// Update
		lowerRTT = currentRTT
		selectedPath = pth
		selectedPathID = pathID
	}

	return selectedPath
}

func (sch *scheduler) selectBLEST(s *session, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) *path {
	// XXX Avoid using PathID 0 if there is more than 1 path
	if len(s.paths) <= 1 {
		if !hasRetransmission && !s.paths[protocol.InitialPathID].SendingAllowed() {
			return nil
		}
		return s.paths[protocol.InitialPathID]
	}

	// FIXME Only works at the beginning... Cope with new paths during the connection
	if hasRetransmission && hasStreamRetransmission && fromPth.rttStats.SmoothedRTT() == 0 {
		// Is there any other path with a lower number of packet sent?
		currentQuota := sch.quotas[fromPth.pathID]
		for pathID, pth := range s.paths {
			if pathID == protocol.InitialPathID || pathID == fromPth.pathID {
				continue
			}
			// The congestion window was checked when duplicating the packet
			if sch.quotas[pathID] < currentQuota {
				return pth
			}
		}
	}

	var bestPath *path
	var secondBestPath *path
	var lowerRTT time.Duration
	var currentRTT time.Duration
	var secondLowerRTT time.Duration
	bestPathID := protocol.PathID(255)

pathLoop:
	for pathID, pth := range s.paths {
		// Don't block path usage if we retransmit, even on another path
		if !hasRetransmission && !pth.SendingAllowed() {
			continue pathLoop
		}

		// If this path is potentially failed, do not consider it for sending
		if pth.potentiallyFailed.Get() {
			continue pathLoop
		}

		// XXX Prevent using initial pathID if multiple paths
		if pathID == protocol.InitialPathID {
			continue pathLoop
		}

		currentRTT = pth.rttStats.SmoothedRTT()

		// Prefer staying single-path if not blocked by current path
		// Don't consider this sample if the smoothed RTT is 0
		if lowerRTT != 0 && currentRTT == 0 {
			continue pathLoop
		}

		// Case if we have multiple paths unprobed
		if currentRTT == 0 {
			currentQuota, ok := sch.quotas[pathID]
			if !ok {
				sch.quotas[pathID] = 0
				currentQuota = 0
			}
			lowerQuota, _ := sch.quotas[bestPathID]
			if bestPath != nil && currentQuota > lowerQuota {
				continue pathLoop
			}
		}

		if currentRTT >= lowerRTT {
			if (secondLowerRTT == 0 || currentRTT < secondLowerRTT) && pth.SendingAllowed() {
				// Update second best available path
				secondLowerRTT = currentRTT
				secondBestPath = pth
			}
			if currentRTT != 0 && lowerRTT != 0 && bestPath != nil {
				continue pathLoop
			}
		}

		// Update
		lowerRTT = currentRTT
		bestPath = pth
		bestPathID = pathID
	}

	if bestPath == nil {
		if secondBestPath != nil {
			return secondBestPath
		}
		return nil
	}

	if hasRetransmission || bestPath.SendingAllowed() {
		return bestPath
	}

	if secondBestPath == nil {
		return nil
	}
	cwndBest := uint64(bestPath.sentPacketHandler.GetCongestionWindow())
	FirstCo := uint64(protocol.DefaultTCPMSS) * uint64(secondLowerRTT) * (cwndBest*2*uint64(lowerRTT) + uint64(secondLowerRTT) - uint64(lowerRTT))
	BSend, _ := s.flowControlManager.SendWindowSize(protocol.StreamID(5))
	SecondCo := 2 * 1 * uint64(lowerRTT) * uint64(lowerRTT) * (uint64(BSend) - (uint64(secondBestPath.sentPacketHandler.GetBytesInFlight()) + uint64(protocol.DefaultTCPMSS)))

	if FirstCo > SecondCo {
		return nil
	} else {
		return secondBestPath
	}
}

func (sch *scheduler) selectECF(s *session, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) *path {
	// XXX Avoid using PathID 0 if there is more than 1 path
	if len(s.paths) <= 1 {
		if !hasRetransmission && !s.paths[protocol.InitialPathID].SendingAllowed() {
			return nil
		}
		return s.paths[protocol.InitialPathID]
	}

	// FIXME Only works at the beginning... Cope with new paths during the connection
	if hasRetransmission && hasStreamRetransmission && fromPth.rttStats.SmoothedRTT() == 0 {
		// Is there any other path with a lower number of packet sent?
		currentQuota := sch.quotas[fromPth.pathID]
		for pathID, pth := range s.paths {
			if pathID == protocol.InitialPathID || pathID == fromPth.pathID {
				continue
			}
			// The congestion window was checked when duplicating the packet
			if sch.quotas[pathID] < currentQuota {
				return pth
			}
		}
	}

	var bestPath *path
	var secondBestPath *path
	var lowerRTT time.Duration
	var currentRTT time.Duration
	var secondLowerRTT time.Duration
	bestPathID := protocol.PathID(255)

pathLoop:
	for pathID, pth := range s.paths {
		// Don't block path usage if we retransmit, even on another path
		if !hasRetransmission && !pth.SendingAllowed() {
			continue pathLoop
		}

		// If this path is potentially failed, do not consider it for sending
		if pth.potentiallyFailed.Get() {
			continue pathLoop
		}

		// XXX Prevent using initial pathID if multiple paths
		if pathID == protocol.InitialPathID {
			continue pathLoop
		}

		currentRTT = pth.rttStats.SmoothedRTT()

		// Prefer staying single-path if not blocked by current path
		// Don't consider this sample if the smoothed RTT is 0
		if lowerRTT != 0 && currentRTT == 0 {
			continue pathLoop
		}

		// Case if we have multiple paths unprobed
		if currentRTT == 0 {
			currentQuota, ok := sch.quotas[pathID]
			if !ok {
				sch.quotas[pathID] = 0
				currentQuota = 0
			}
			lowerQuota, _ := sch.quotas[bestPathID]
			if bestPath != nil && currentQuota > lowerQuota {
				continue pathLoop
			}
		}

		if currentRTT >= lowerRTT {
			if (secondLowerRTT == 0 || currentRTT < secondLowerRTT) && pth.SendingAllowed() {
				// Update second best available path
				secondLowerRTT = currentRTT
				secondBestPath = pth
			}
			if currentRTT != 0 && lowerRTT != 0 && bestPath != nil {
				continue pathLoop
			}
		}

		// Update
		lowerRTT = currentRTT
		bestPath = pth
		bestPathID = pathID
	}

	if bestPath == nil {
		if secondBestPath != nil {
			return secondBestPath
		}
		return nil
	}

	if hasRetransmission || bestPath.SendingAllowed() {
		return bestPath
	}

	if secondBestPath == nil {
		return nil
	}

	var queueSize uint64
	getQueueSize := func(s *stream) (bool, error) {
		if s != nil {
			queueSize = queueSize + uint64(s.lenOfDataForWriting())
		}
		return true, nil
	}
	s.streamsMap.Iterate(getQueueSize)

	cwndBest := uint64(bestPath.sentPacketHandler.GetCongestionWindow())
	cwndSecond := uint64(secondBestPath.sentPacketHandler.GetCongestionWindow())
	deviationBest := uint64(bestPath.rttStats.MeanDeviation())
	deviationSecond := uint64(secondBestPath.rttStats.MeanDeviation())

	delta := deviationBest
	if deviationBest < deviationSecond {
		delta = deviationSecond
	}
	xBest := queueSize
	if queueSize < cwndBest {
		xBest = cwndBest
	}

	lhs := uint64(lowerRTT) * (xBest + cwndBest)
	rhs := cwndBest * (uint64(secondLowerRTT) + delta)
	if (lhs * 4) < ((rhs * 4) + sch.waiting*rhs) {
		xSecond := queueSize
		if queueSize < cwndSecond {
			xSecond = cwndSecond
		}
		lhsSecond := uint64(secondLowerRTT) * xSecond
		rhsSecond := cwndSecond * (2*uint64(lowerRTT) + delta)
		if lhsSecond > rhsSecond {
			sch.waiting = 1
			return nil
		}
	} else {
		sch.waiting = 0
	}

	return secondBestPath
}

func (sch *scheduler) selectPathLowBandit(s *session, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) *path {
	// XXX Avoid using PathID 0 if there is more than 1 path
	if len(s.paths) <= 1 {
		if !hasRetransmission && !s.paths[protocol.InitialPathID].SendingAllowed() {
			return nil
		}
		return s.paths[protocol.InitialPathID]
	}

	// FIXME Only works at the beginning... Cope with new paths during the connection
	if hasRetransmission && hasStreamRetransmission && fromPth.rttStats.SmoothedRTT() == 0 {
		// Is there any other path with a lower number of packet sent?
		currentQuota := sch.quotas[fromPth.pathID]
		for pathID, pth := range s.paths {
			if pathID == protocol.InitialPathID || pathID == fromPth.pathID {
				continue
			}
			// The congestion window was checked when duplicating the packet
			if sch.quotas[pathID] < currentQuota {
				return pth
			}
		}
	}

	var bestPath *path
	var secondBestPath *path
	var lowerRTT time.Duration
	var currentRTT time.Duration
	var secondLowerRTT time.Duration
	bestPathID := protocol.PathID(255)

pathLoop:
	for pathID, pth := range s.paths {
		// If this path is potentially failed, do not consider it for sending
		if pth.potentiallyFailed.Get() {
			continue pathLoop
		}

		// XXX Prevent using initial pathID if multiple paths
		if pathID == protocol.InitialPathID {
			continue pathLoop
		}

		currentRTT = pth.rttStats.SmoothedRTT()

		// Prefer staying single-path if not blocked by current path
		// Don't consider this sample if the smoothed RTT is 0
		if lowerRTT != 0 && currentRTT == 0 {
			continue pathLoop
		}

		// Case if we have multiple paths unprobed
		if currentRTT == 0 {
			currentQuota, ok := sch.quotas[pathID]
			if !ok {
				sch.quotas[pathID] = 0
				currentQuota = 0
			}
			lowerQuota, _ := sch.quotas[bestPathID]
			if bestPath != nil && currentQuota > lowerQuota {
				continue pathLoop
			}
		}

		if currentRTT >= lowerRTT {
			if (secondLowerRTT == 0 || currentRTT < secondLowerRTT) && pth.SendingAllowed() {
				// Update second best available path
				secondLowerRTT = currentRTT
				secondBestPath = pth
			}
			if currentRTT != 0 && lowerRTT != 0 && bestPath != nil {
				continue pathLoop
			}
		}

		// Update
		lowerRTT = currentRTT
		bestPath = pth
		bestPathID = pathID

	}

	//Get reward and Update Aa, ba
	if bestPath != nil && secondBestPath != nil {
		for sch.episoderecord < sch.record {
			// Get reward
			cureNum := uint64(0)
			curereward := float64(0)
			if sch.actionvector[sch.episoderecord] == 0 {
				cureNum = uint64(bestPath.sentPacketHandler.GetLeastUnacked() - 1)
			} else {
				cureNum = uint64(secondBestPath.sentPacketHandler.GetLeastUnacked() - 1)
			}
			if sch.packetvector[sch.episoderecord] <= cureNum {
				curereward = float64(protocol.DefaultTCPMSS) / float64(time.Since(sch.zz[sch.episoderecord]))
			} else {
				break
			}
			//Update Aa, ba
			feature := mat.NewDense(banditDimension, 1, nil)
			feature.Set(0, 0, sch.featureone[sch.episoderecord])
			feature.Set(1, 0, sch.featuretwo[sch.episoderecord])
			feature.Set(2, 0, sch.featurethree[sch.episoderecord])
			feature.Set(3, 0, sch.featurefour[sch.episoderecord])
			feature.Set(4, 0, sch.featurefive[sch.episoderecord])
			feature.Set(5, 0, sch.featuresix[sch.episoderecord])

			if sch.actionvector[sch.episoderecord] == 0 {
				rewardMul := mat.NewDense(banditDimension, 1, nil)
				rewardMul.Scale(curereward, feature)
				baF := mat.NewDense(banditDimension, 1, nil)
				for i := 0; i < banditDimension; i++ {
					baF.Set(i, 0, sch.MbaF[i])
				}
				baF.Add(baF, rewardMul)
				for i := 0; i < banditDimension; i++ {
					sch.MbaF[i] = baF.At(i, 0)
				}
				featureMul := mat.NewDense(banditDimension, banditDimension, nil)
				featureMul.Product(feature, feature.T())
				AaF := mat.NewDense(banditDimension, banditDimension, nil)
				for i := 0; i < banditDimension; i++ {
					for j := 0; j < banditDimension; j++ {
						AaF.Set(i, j, sch.MAaF[i][j])
					}
				}
				AaF.Add(AaF, featureMul)
				for i := 0; i < banditDimension; i++ {
					for j := 0; j < banditDimension; j++ {
						sch.MAaF[i][j] = AaF.At(i, j)
					}
				}
				sch.fe += 1
			} else {
				rewardMul := mat.NewDense(banditDimension, 1, nil)
				rewardMul.Scale(curereward, feature)
				baS := mat.NewDense(banditDimension, 1, nil)
				for i := 0; i < banditDimension; i++ {
					baS.Set(i, 0, sch.MbaS[i])
				}
				baS.Add(baS, rewardMul)
				for i := 0; i < banditDimension; i++ {
					sch.MbaS[i] = baS.At(i, 0)
				}
				featureMul := mat.NewDense(banditDimension, banditDimension, nil)
				featureMul.Product(feature, feature.T())
				AaS := mat.NewDense(banditDimension, banditDimension, nil)
				for i := 0; i < banditDimension; i++ {
					for j := 0; j < banditDimension; j++ {
						AaS.Set(i, j, sch.MAaS[i][j])
					}
				}
				AaS.Add(AaS, featureMul)
				for i := 0; i < banditDimension; i++ {
					for j := 0; j < banditDimension; j++ {
						sch.MAaS[i][j] = AaS.At(i, j)
					}
				}
				sch.se += 1
			}
			//Update pointer
			sch.episoderecord += 1
		}
	}

	if bestPath == nil {
		if secondBestPath != nil {
			return secondBestPath
		}
		if s.paths[protocol.InitialPathID].SendingAllowed() || hasRetransmission {
			return s.paths[protocol.InitialPathID]
		} else {
			return nil
		}
	}
	if bestPath.SendingAllowed() {
		sch.waiting = 0
		return bestPath
	}
	if secondBestPath == nil {
		if s.paths[protocol.InitialPathID].SendingAllowed() || hasRetransmission {
			return s.paths[protocol.InitialPathID]
		} else {
			return nil
		}
	}

	if hasRetransmission && secondBestPath.SendingAllowed() {
		return secondBestPath
	}
	if hasRetransmission {
		return s.paths[protocol.InitialPathID]
	}

	if sch.waiting == 1 {
		return nil
	} else {
		// Migrate from buffer to local variables
		AaF := mat.NewDense(banditDimension, banditDimension, nil)
		for i := 0; i < banditDimension; i++ {
			for j := 0; j < banditDimension; j++ {
				AaF.Set(i, j, sch.MAaF[i][j])
			}
		}
		AaS := mat.NewDense(banditDimension, banditDimension, nil)
		for i := 0; i < banditDimension; i++ {
			for j := 0; j < banditDimension; j++ {
				AaS.Set(i, j, sch.MAaS[i][j])
			}
		}
		baF := mat.NewDense(banditDimension, 1, nil)
		for i := 0; i < banditDimension; i++ {
			baF.Set(i, 0, sch.MbaF[i])
		}
		baS := mat.NewDense(banditDimension, 1, nil)
		for i := 0; i < banditDimension; i++ {
			baS.Set(i, 0, sch.MbaS[i])
		}

		//Features
		cwndBest := float64(bestPath.sentPacketHandler.GetCongestionWindow())
		cwndSecond := float64(secondBestPath.sentPacketHandler.GetCongestionWindow())
		BSend, _ := s.flowControlManager.SendWindowSize(protocol.StreamID(5))
		inflightf := float64(bestPath.sentPacketHandler.GetBytesInFlight())
		inflights := float64(secondBestPath.sentPacketHandler.GetBytesInFlight())
		llowerRTT := bestPath.rttStats.LatestRTT()
		lsecondLowerRTT := secondBestPath.rttStats.LatestRTT()
		feature := mat.NewDense(banditDimension, 1, nil)
		if 0 < float64(lsecondLowerRTT) && 0 < float64(llowerRTT) {
			feature.Set(0, 0, cwndBest/float64(llowerRTT))
			feature.Set(2, 0, float64(BSend)/float64(llowerRTT))
			feature.Set(4, 0, inflightf/float64(llowerRTT))
			feature.Set(1, 0, inflights/float64(lsecondLowerRTT))
			feature.Set(3, 0, float64(BSend)/float64(lsecondLowerRTT))
			feature.Set(5, 0, cwndSecond/float64(lsecondLowerRTT))
		} else {
			feature.Set(0, 0, 0)
			feature.Set(2, 0, 0)
			feature.Set(4, 0, 0)
			feature.Set(1, 0, 0)
			feature.Set(3, 0, 0)
			feature.Set(5, 0, 0)
		}

		//Buffer feature for latter update
		sch.featureone[sch.record] = feature.At(0, 0)
		sch.featuretwo[sch.record] = feature.At(1, 0)
		sch.featurethree[sch.record] = feature.At(2, 0)
		sch.featurefour[sch.record] = feature.At(3, 0)
		sch.featurefive[sch.record] = feature.At(4, 0)
		sch.featuresix[sch.record] = feature.At(5, 0)

		//Obtain theta
		AaIF := mat.NewDense(banditDimension, banditDimension, nil)
		AaIF.Inverse(AaF)
		thetaF := mat.NewDense(banditDimension, 1, nil)
		thetaF.Product(AaIF, baF)

		AaIS := mat.NewDense(banditDimension, banditDimension, nil)
		AaIS.Inverse(AaS)
		thetaS := mat.NewDense(banditDimension, 1, nil)
		thetaS.Product(AaIS, baS)

		//Obtain bandit value
		thetaFPro := mat.NewDense(1, 1, nil)
		thetaFPro.Product(thetaF.T(), feature)
		featureFProOne := mat.NewDense(1, banditDimension, nil)
		featureFProOne.Product(feature.T(), AaIF)
		featureFProTwo := mat.NewDense(1, 1, nil)
		featureFProTwo.Product(featureFProOne, feature)

		thetaSPro := mat.NewDense(1, 1, nil)
		thetaSPro.Product(thetaS.T(), feature)
		featureSProOne := mat.NewDense(1, banditDimension, nil)
		featureSProOne.Product(feature.T(), AaIS)
		featureSProTwo := mat.NewDense(1, 1, nil)
		featureSProTwo.Product(featureSProOne, feature)

		//Make decision based on bandit value
		if (thetaSPro.At(0, 0) + banditAlpha*math.Sqrt(featureSProTwo.At(0, 0))) < (thetaFPro.At(0, 0) + banditAlpha*math.Sqrt(featureFProTwo.At(0, 0))) {
			sch.waiting = 1
			sch.zz[sch.record] = time.Now()
			sch.actionvector[sch.record] = 0
			sch.packetvector[sch.record] = bestPath.sentPacketHandler.GetLastPackets() + 1
			sch.record += 1
			return nil
		} else {
			sch.waiting = 0
			sch.zz[sch.record] = time.Now()
			sch.actionvector[sch.record] = 1
			sch.packetvector[sch.record] = secondBestPath.sentPacketHandler.GetLastPackets() + 1
			sch.record += 1
			return secondBestPath
		}

	}

}

func (sch *scheduler) selectPathPeek(s *session, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) *path {
	// XXX Avoid using PathID 0 if there is more than 1 path
	if len(s.paths) <= 1 {
		if !hasRetransmission && !s.paths[protocol.InitialPathID].SendingAllowed() {
			return nil
		}
		return s.paths[protocol.InitialPathID]
	}

	// FIXME Only works at the beginning... Cope with new paths during the connection
	if hasRetransmission && hasStreamRetransmission && fromPth.rttStats.SmoothedRTT() == 0 {
		// Is there any other path with a lower number of packet sent?
		currentQuota := sch.quotas[fromPth.pathID]
		for pathID, pth := range s.paths {
			if pathID == protocol.InitialPathID || pathID == fromPth.pathID {
				continue
			}
			// The congestion window was checked when duplicating the packet
			if sch.quotas[pathID] < currentQuota {
				return pth
			}
		}
	}

	var bestPath *path
	var secondBestPath *path
	var lowerRTT time.Duration
	var currentRTT time.Duration
	var secondLowerRTT time.Duration
	bestPathID := protocol.PathID(255)

pathLoop:
	for pathID, pth := range s.paths {
		// If this path is potentially failed, do not consider it for sending
		if pth.potentiallyFailed.Get() {
			continue pathLoop
		}

		// XXX Prevent using initial pathID if multiple paths
		if pathID == protocol.InitialPathID {
			continue pathLoop
		}

		currentRTT = pth.rttStats.SmoothedRTT()

		// Prefer staying single-path if not blocked by current path
		// Don't consider this sample if the smoothed RTT is 0
		if lowerRTT != 0 && currentRTT == 0 {
			continue pathLoop
		}

		// Case if we have multiple paths unprobed
		if currentRTT == 0 {
			currentQuota, ok := sch.quotas[pathID]
			if !ok {
				sch.quotas[pathID] = 0
				currentQuota = 0
			}
			lowerQuota, _ := sch.quotas[bestPathID]
			if bestPath != nil && currentQuota > lowerQuota {
				continue pathLoop
			}
		}

		if currentRTT >= lowerRTT {
			if (secondLowerRTT == 0 || currentRTT < secondLowerRTT) && pth.SendingAllowed() {
				// Update second best available path
				secondLowerRTT = currentRTT
				secondBestPath = pth
			}
			if currentRTT != 0 && lowerRTT != 0 && bestPath != nil {
				continue pathLoop
			}
		}

		// Update
		lowerRTT = currentRTT
		bestPath = pth
		bestPathID = pathID

	}

	if bestPath == nil {
		if secondBestPath != nil {
			return secondBestPath
		}
		if s.paths[protocol.InitialPathID].SendingAllowed() || hasRetransmission {
			return s.paths[protocol.InitialPathID]
		} else {
			return nil
		}
	}
	if bestPath.SendingAllowed() {
		sch.waiting = 0
		return bestPath
	}
	if secondBestPath == nil {
		if s.paths[protocol.InitialPathID].SendingAllowed() || hasRetransmission {
			return s.paths[protocol.InitialPathID]
		} else {
			return nil
		}
	}

	if hasRetransmission && secondBestPath.SendingAllowed() {
		return secondBestPath
	}
	if hasRetransmission {
		return s.paths[protocol.InitialPathID]
	}

	if sch.waiting == 1 {
		return nil
	} else {
		// Migrate from buffer to local variables
		AaF := mat.NewDense(banditDimension, banditDimension, nil)
		for i := 0; i < banditDimension; i++ {
			for j := 0; j < banditDimension; j++ {
				AaF.Set(i, j, sch.MAaF[i][j])
			}
		}
		AaS := mat.NewDense(banditDimension, banditDimension, nil)
		for i := 0; i < banditDimension; i++ {
			for j := 0; j < banditDimension; j++ {
				AaS.Set(i, j, sch.MAaS[i][j])
			}
		}
		baF := mat.NewDense(banditDimension, 1, nil)
		for i := 0; i < banditDimension; i++ {
			baF.Set(i, 0, sch.MbaF[i])
		}
		baS := mat.NewDense(banditDimension, 1, nil)
		for i := 0; i < banditDimension; i++ {
			baS.Set(i, 0, sch.MbaS[i])
		}

		//Features
		cwndBest := float64(bestPath.sentPacketHandler.GetCongestionWindow())
		cwndSecond := float64(secondBestPath.sentPacketHandler.GetCongestionWindow())
		BSend, _ := s.flowControlManager.SendWindowSize(protocol.StreamID(5))
		inflightf := float64(bestPath.sentPacketHandler.GetBytesInFlight())
		inflights := float64(secondBestPath.sentPacketHandler.GetBytesInFlight())
		llowerRTT := bestPath.rttStats.LatestRTT()
		lsecondLowerRTT := secondBestPath.rttStats.LatestRTT()
		feature := mat.NewDense(banditDimension, 1, nil)
		if 0 < float64(lsecondLowerRTT) && 0 < float64(llowerRTT) {
			feature.Set(0, 0, cwndBest/float64(llowerRTT))
			feature.Set(2, 0, float64(BSend)/float64(llowerRTT))
			feature.Set(4, 0, inflightf/float64(llowerRTT))
			feature.Set(1, 0, inflights/float64(lsecondLowerRTT))
			feature.Set(3, 0, float64(BSend)/float64(lsecondLowerRTT))
			feature.Set(5, 0, cwndSecond/float64(lsecondLowerRTT))
		} else {
			feature.Set(0, 0, 0)
			feature.Set(2, 0, 0)
			feature.Set(4, 0, 0)
			feature.Set(1, 0, 0)
			feature.Set(3, 0, 0)
			feature.Set(5, 0, 0)
		}

		//Obtain theta
		AaIF := mat.NewDense(banditDimension, banditDimension, nil)
		AaIF.Inverse(AaF)
		thetaF := mat.NewDense(banditDimension, 1, nil)
		thetaF.Product(AaIF, baF)

		AaIS := mat.NewDense(banditDimension, banditDimension, nil)
		AaIS.Inverse(AaS)
		thetaS := mat.NewDense(banditDimension, 1, nil)
		thetaS.Product(AaIS, baS)

		//Obtain bandit value
		thetaFPro := mat.NewDense(1, 1, nil)
		thetaFPro.Product(thetaF.T(), feature)

		thetaSPro := mat.NewDense(1, 1, nil)
		thetaSPro.Product(thetaS.T(), feature)

		//Make decision based on bandit value and stochastic value
		if thetaSPro.At(0, 0) < thetaFPro.At(0, 0) {
			if rand.Intn(100) < 70 {
				sch.waiting = 1
				return nil
			} else {
				sch.waiting = 0
				return secondBestPath
			}
		} else {
			if rand.Intn(100) < 90 {
				sch.waiting = 0
				return secondBestPath
			} else {
				sch.waiting = 1
				return nil
			}
		}
	}

}

func (sch *scheduler) selectPathRandom(s *session, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) *path {
	// XXX Avoid using PathID 0 if there is more than 1 path
	if len(s.paths) <= 1 {
		if !hasRetransmission && !s.paths[protocol.InitialPathID].SendingAllowed() {
			return nil
		}
		return s.paths[protocol.InitialPathID]
	}
	var availablePaths []protocol.PathID

	for pathID, pth := range s.paths {
		cong := float32(pth.sentPacketHandler.GetCongestionWindow()) - float32(pth.sentPacketHandler.GetBytesInFlight())
		allowed := pth.SendingAllowed() || (cong <= 0 && float32(cong) >= -float32(pth.sentPacketHandler.GetCongestionWindow())*float32(sch.AllowedCongestion)*0.01)

		if pathID != protocol.InitialPathID && (allowed || hasRetransmission) {
			//if pathID != protocol.InitialPathID && (pth.SendingAllowed() || hasRetransmission){
			availablePaths = append(availablePaths, pathID)
		}
	}

	if len(availablePaths) == 0 {
		return nil
	}

	pathID := rand.Intn(len(availablePaths))
	utils.Debugf("Selecting path %d", pathID)
	return s.paths[availablePaths[pathID]]
}

func (sch *scheduler) selectFirstPath(s *session, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) *path {
	if len(s.paths) <= 1 {
		if !hasRetransmission && !s.paths[protocol.InitialPathID].SendingAllowed() {
			return nil
		}
		return s.paths[protocol.InitialPathID]
	}
	for pathID, pth := range s.paths {
		if pathID == protocol.PathID(1) && pth.SendingAllowed() {
			return pth
		}
	}

	return nil
}

// Lock of s.paths must be held
func (sch *scheduler) selectPath(s *session, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) *path {
	//fmt.Println("Selecting path")
	switch s.config.Scheduler {
	case constants.SCHEDULER_ROUND_ROBIN:
		return sch.selectPathRoundRobin(s, hasRetransmission, hasStreamRetransmission, fromPth)
	case constants.SCHEDULER_LOW_LATENCY:
		return sch.selectPathLowLatency(s, hasRetransmission, hasStreamRetransmission, fromPth)
	case constants.SCHEDULER_FIRST_PATH:
		return sch.selectFirstPath(s, hasRetransmission, hasStreamRetransmission, fromPth)
	case constants.SCHEDULER_BLEST:
		return sch.selectBLEST(s, hasRetransmission, hasStreamRetransmission, fromPth)
	case constants.SCHEDULER_ECF:
		return sch.selectECF(s, hasRetransmission, hasStreamRetransmission, fromPth)
	case constants.SCHEDULER_LOW_BANDIT:
		return sch.selectPathLowBandit(s, hasRetransmission, hasStreamRetransmission, fromPth)
	case constants.SCHEDULER_PEEKABOO:
		return sch.selectPathPeek(s, hasRetransmission, hasStreamRetransmission, fromPth)
	case constants.SCHEDULER_RANDOM:
		return sch.selectPathRandom(s, hasRetransmission, hasStreamRetransmission, fromPth)
	// zzh: add new scheduler
	case constants.SCHEDULER_ARRIVAL_TIME:
		return sch.mySelectPathByArrivalTime(s, hasRetransmission, hasStreamRetransmission, fromPth)
	default:
		return sch.selectPathRoundRobin(s, hasRetransmission, hasStreamRetransmission, fromPth)
	}
}

// Lock of s.paths must be free (in case of log print)
func (sch *scheduler) performPacketSending(s *session, windowUpdateFrames []*wire.WindowUpdateFrame, pth *path) (*ackhandler.Packet, bool, error) {
	// add a retransmittable frame
	if pth.sentPacketHandler.ShouldSendRetransmittablePacket() {
		s.packer.QueueControlFrame(&wire.PingFrame{}, pth)
	}
	packet, err := s.packer.PackPacket(pth)
	if err != nil || packet == nil {
		return nil, false, err
	}
	if err = s.sendPackedPacket(packet, pth); err != nil {
		return nil, false, err
	}

	// send every window update twice
	for _, f := range windowUpdateFrames {
		s.packer.QueueControlFrame(f, pth)
	}

	// Packet sent, so update its quota
	sch.quotas[pth.pathID]++

	sRTT := make(map[protocol.PathID]time.Duration)

	// Provide some logging if it is the last packet
	for _, frame := range packet.frames {
		switch frame := frame.(type) {
		case *wire.StreamFrame:
			if frame.FinBit {
				// Last packet to send on the stream, print stats
				s.pathsLock.RLock()
				utils.Infof("Info for stream %x of %x", frame.StreamID, s.connectionID)
				for pathID, pth := range s.paths {
					sntPkts, sntRetrans, sntLost := pth.sentPacketHandler.GetStatistics()
					rcvPkts := pth.receivedPacketHandler.GetStatistics()
					utils.Infof("Path %x: sent %d retrans %d lost %d; rcv %d rtt %v", pathID, sntPkts, sntRetrans, sntLost, rcvPkts, pth.rttStats.SmoothedRTT())
					//utils.Infof("Congestion Window: %d", pth.sentPacketHandler.GetCongestionWindow())
					if sch.Training {
						sRTT[pathID] = pth.rttStats.SmoothedRTT()
					}
				}

				if sch.DumpExp && !sch.Training && sch.SchedulerName == "dqnAgent" {
					utils.Infof("Closing episode %d", uint64(s.connectionID))
					sch.dumpAgent.CloseExperience(uint64(s.connectionID))
				}
				s.pathsLock.RUnlock()
				//Write lin parameters
				os.Remove(sch.projectHomeDir + "/sch_out/lin")
				os.Create(sch.projectHomeDir + "/sch_out/lin")
				file2, _ := os.OpenFile(sch.projectHomeDir+"/sch_out/lin", os.O_WRONLY, 0600)
				for i := 0; i < banditDimension; i++ {
					for j := 0; j < banditDimension; j++ {
						fmt.Fprintf(file2, "%.8f\n", sch.MAaF[i][j])
					}
				}
				for i := 0; i < banditDimension; i++ {
					for j := 0; j < banditDimension; j++ {
						fmt.Fprintf(file2, "%.8f\n", sch.MAaS[i][j])
					}
				}
				for j := 0; j < banditDimension; j++ {
					fmt.Fprintf(file2, "%.8f\n", sch.MbaF[j])
				}
				for j := 0; j < banditDimension; j++ {
					fmt.Fprintf(file2, "%.8f\n", sch.MbaS[j])
				}
				file2.Close()
			}
		default:
		}
	}

	pkt := &ackhandler.Packet{
		PacketNumber:    packet.number,
		Frames:          packet.frames,
		Length:          protocol.ByteCount(len(packet.raw)),
		EncryptionLevel: packet.encryptionLevel,
	}

	return pkt, true, nil
}

// Lock of s.paths must be free
func (sch *scheduler) ackRemainingPaths(s *session, totalWindowUpdateFrames []*wire.WindowUpdateFrame) error {
	// Either we run out of data, or CWIN of usable paths are full
	// Send ACKs on paths not yet used, if needed. Either we have no data to send and
	// it will be a pure ACK, or we will have data in it, but the CWIN should then
	// not be an issue.
	s.pathsLock.RLock()
	defer s.pathsLock.RUnlock()
	// get WindowUpdate frames
	// this call triggers the flow controller to increase the flow control windows, if necessary
	windowUpdateFrames := totalWindowUpdateFrames
	if len(windowUpdateFrames) == 0 {
		windowUpdateFrames = s.getWindowUpdateFrames(s.peerBlocked)
	}
	for _, pthTmp := range s.paths {
		ackTmp := pthTmp.GetAckFrame()
		for _, wuf := range windowUpdateFrames {
			s.packer.QueueControlFrame(wuf, pthTmp)
		}
		if ackTmp != nil || len(windowUpdateFrames) > 0 {
			if pthTmp.pathID == protocol.InitialPathID && ackTmp == nil {
				continue
			}
			swf := pthTmp.GetStopWaitingFrame(false)
			if swf != nil {
				s.packer.QueueControlFrame(swf, pthTmp)
			}
			s.packer.QueueControlFrame(ackTmp, pthTmp)
			// XXX (QDC) should we instead call PackPacket to provides WUFs?
			var packet *packedPacket
			var err error
			if ackTmp != nil {
				// Avoid internal error bug
				packet, err = s.packer.PackAckPacket(pthTmp)
			} else {
				packet, err = s.packer.PackPacket(pthTmp)
			}
			if err != nil {
				return err
			}
			err = s.sendPackedPacket(packet, pthTmp)
			if err != nil {
				return err
			}
		}
	}
	s.peerBlocked = false
	return nil
}

func (sch *scheduler) sendPacket(s *session) error {
	var pth *path

	// Update leastUnacked value of paths
	s.pathsLock.RLock()
	for _, pthTmp := range s.paths {
		pthTmp.SetLeastUnacked(pthTmp.sentPacketHandler.GetLeastUnacked())
	}
	s.pathsLock.RUnlock()

	// get WindowUpdate frames
	// this call triggers the flow controller to increase the flow control windows, if necessary
	windowUpdateFrames := s.getWindowUpdateFrames(false)
	for _, wuf := range windowUpdateFrames {
		s.packer.QueueControlFrame(wuf, pth)
	}

	// Repeatedly try sending until we don't have any more data, or run out of the congestion window
	// zzh: OR packetsNotSentYet is not empty! TODO
	i := 0
	for {
		i++
		utils.Debugf("zzh: =========================loop of sendPacketOriginal() IN Round No.%d============================", i)
		// We first check for retransmissions
		hasRetransmission, retransmitHandshakePacket, fromPth := sch.getRetransmission(s)
		// XXX There might still be some stream frames to be retransmitted
		hasStreamRetransmission := s.streamFramer.HasFramesForRetransmission()

		// Select the path here
		s.pathsLock.RLock()
		pth = sch.selectPath(s, hasRetransmission, hasStreamRetransmission, fromPth)
		s.pathsLock.RUnlock()

		// zzh: debug
		// s.pathsLock.RUnlock()
		if pth != nil {
			sch.pthtoarrive = pth
			utils.Debugf("zzh: send on path %v", pth.pathID)
		} else {
			utils.Debugf("zzh: path nil!")
		}

		// arriveTime, ok := sch.calculateArrivalTimefromsendbuffer(s, sch.pthtoarrive, false)
		// if ok {
		// 	fmt.Println("zzh: arriveTime: ", arriveTime)
		// 	if arriveTime >= time.Duration(deadline) {
		// 		fmt.Println(arriveTime, deadline)
		// 		utils.Debugf("zzh: The deadline has been exceeded\n")
		// 		s.exceed_deadline.Set(true)
		// 	} else {
		// 		utils.Debugf("zzh: The deadline has not been exceeded\n")
		// 		s.exceed_deadline.Set(false)
		// 	}
		// 	utils.Debugf("zzh: arriveTime: %v", arriveTime)
		// } else {
		// 	utils.Debugf("zzh: arriveTime: nil")
		// }

		// XXX No more path available, should we have a new QUIC error message?
		if pth == nil {
			windowUpdateFrames := s.getWindowUpdateFrames(false)
			return sch.ackRemainingPaths(s, windowUpdateFrames)
		}

		// If we have an handshake packet retransmission, do it directly
		if hasRetransmission && retransmitHandshakePacket != nil {
			s.packer.QueueControlFrame(pth.sentPacketHandler.GetStopWaitingFrame(true), pth)
			packet, err := s.packer.PackHandshakeRetransmission(retransmitHandshakePacket, pth)
			if err != nil {
				return err
			}
			if err = s.sendPackedPacket(packet, pth); err != nil {
				utils.Debugf("zzh: sendPackedPacket, we have an handshake packet retransmission")
				return err
			}
			continue
		}

		// XXX Some automatic ACK generation should be done someway
		var ack *wire.AckFrame

		ack = pth.GetAckFrame()
		if ack != nil {
			s.packer.QueueControlFrame(ack, pth)
		}
		if ack != nil || hasStreamRetransmission {
			swf := pth.sentPacketHandler.GetStopWaitingFrame(hasStreamRetransmission)
			if swf != nil {
				s.packer.QueueControlFrame(swf, pth)
			}
		}

		// Also add CLOSE_PATH frames, if any
		for cpf := s.streamFramer.PopClosePathFrame(); cpf != nil; cpf = s.streamFramer.PopClosePathFrame() {
			s.packer.QueueControlFrame(cpf, pth)
		}

		// Also add ADD ADDRESS frames, if any
		for aaf := s.streamFramer.PopAddAddressFrame(); aaf != nil; aaf = s.streamFramer.PopAddAddressFrame() {
			s.packer.QueueControlFrame(aaf, pth)
		}

		// Also add PATHS frames, if any
		for pf := s.streamFramer.PopPathsFrame(); pf != nil; pf = s.streamFramer.PopPathsFrame() {
			s.packer.QueueControlFrame(pf, pth)
		}

		// pkt, sent, err := sch.performPacketSending(s, windowUpdateFrames, pth)
		pkt, sent, err := sch.performPacketSendingOfMine(s, windowUpdateFrames, pth) //zzh: HERE!! finally send a pkt
		if err != nil {
			if err == ackhandler.ErrTooManyTrackedSentPackets {
				utils.Errorf("Closing episode")
			}
			return err
		}
		windowUpdateFrames = nil
		// zzh: add debug
		if sent && pkt == nil {
			utils.Debugf("zzh: sent && pkt == nil")
			continue
		}

		if !sent {
			// Prevent sending empty packets
			return sch.ackRemainingPaths(s, windowUpdateFrames)
		}

		// Duplicate traffic when it was sent on an unknown performing path
		// FIXME adapt for new paths coming during the connection
		if pth.rttStats.SmoothedRTT() == 0 {
			currentQuota := sch.quotas[pth.pathID]
			// Was the packet duplicated on all potential paths?
		duplicateLoop:
			for pathID, tmpPth := range s.paths {
				if pathID == protocol.InitialPathID || pathID == pth.pathID {
					continue
				}
				if sch.quotas[pathID] < currentQuota && tmpPth.sentPacketHandler.SendingAllowed() {
					// Duplicate it
					pth.sentPacketHandler.DuplicatePacket(pkt)
					break duplicateLoop
				}
			}
		}

		// And try pinging on potentially failed paths
		if fromPth != nil && fromPth.potentiallyFailed.Get() {
			err = s.sendPing(fromPth)
			if err != nil {
				return err
			}
		}
	}
}

func PrintSchedulerInfo(config *Config) {
	// Scheduler Info
	schedulerList := []string{constants.SCHEDULER_ROUND_ROBIN, constants.SCHEDULER_LOW_LATENCY,
		constants.SCHEDULER_PEEKABOO, constants.SCHEDULER_ECF, constants.SCHEDULER_DQNA, constants.SCHEDULER_BLEST,
		constants.SCHEDULER_FIRST_PATH, constants.SCHEDULER_LOW_BANDIT, constants.SCHEDULER_RANDOM,
		constants.SCHEDULER_ARRIVAL_TIME}
	if config.Scheduler == "" {
		fmt.Println("Using Default Multipath Scheduler: ", constants.SCHEDULER_ROUND_ROBIN)
	} else if util.StringInSlice(schedulerList, config.Scheduler) {
		fmt.Println("Selected Multipath Scheduler:", config.Scheduler)
	} else {
		fmt.Printf("Invalid Multipath Scheduler selected, defaulting to %s\n Available schedulers: %s\n",
			constants.SCHEDULER_ROUND_ROBIN, schedulerList)
	}
}

// zzh: begin from ytxing's code
/*
	zzh:	Here we got a specific stream selected by myChooseStream, and

/			we choose a path with shortest packet arrival time.
/			Calculate pkt arrival time by assuming that the next packet is
/			of the maxSize.
*/
func (sch *scheduler) mySelectPathByArrivalTime(s *session, hasRetransmission bool, hasStreamRetransmission bool, fromPth *path) (selectedPath *path) {
	utils.Debugf("zzh: mySelectPathByArrivalTime() IN\n")
	defer utils.Debugf("zzh:  mySelectPathByArrivalTime() OUT\n")
	// if s.perspective == protocol.PerspectiveClient {
	// 	//zzh: why client always use the path with minRTT
	// 	utils.Debugf("zzh: I am client, use minRTT\n")
	// 	return sch.selectPathLowLatency(s, hasRetransmission, hasStreamRetransmission, fromPth)
	// }
	// XXX Avoid using PathID 0 if there is more than 1 path
	if len(s.paths) <= 1 {
		if !s.paths[protocol.InitialPathID].SendingAllowed() {
			return nil
		}
		selectedPath = s.paths[protocol.InitialPathID]
		return selectedPath
	}
	// FIXME Only works at the beginning... Cope with new paths during the connection
	if hasRetransmission && hasStreamRetransmission && fromPth.rttStats.SmoothedRTT() == 0 {
		// Is there any other path with a lower number of packet sent?
		currentQuota := sch.quotas[fromPth.pathID]
		for pathID, pth := range s.paths {
			if pathID == protocol.InitialPathID || pathID == fromPth.pathID {
				continue
			}
			// The congestion window was checked when duplicating the packet
			if sch.quotas[pathID] < currentQuota {
				utils.Debugf("zzh: Strange return path %v\n", pth.pathID)
				return pth
			}
		}
	}

	// zzh: not necessary
	for _, pth := range s.paths {
		if pth != nil && !sch.sendingQueueEmpty(pth) {
			if pth.SendingAllowed() {
				utils.Debugf("zzh: when selecting path, find path %v can send some stored frames\n", pth.pathID)
				return pth
			}
			utils.Debugf("zzh: when selecting path, find path %v can send some stored frames but blocked\n", pth.pathID)
		}
	}
	// var currentRTT time.Duration
	var currentArrivalTime time.Duration
	var lowerArrivalTime time.Duration
	selectedPathID := protocol.PathID(255)
	// zzh: use all paths
	var allCwndLimited bool = true

	//find the best path, including that is limited by SendingAllowed()
pathLoop:
	for pathID, pth := range s.paths {

		// If this path is potentially failed, do not consider it for sending
		if pth.potentiallyFailed.Get() {
			// utils.Debugf("zzh: path %v pth.potentiallyFailed.Get(), pass it", pathID)
			continue pathLoop
		}

		// XXX Prevent using initial pathID if multiple paths
		if pathID == protocol.InitialPathID {
			// utils.Debugf("zzh: path %v pathID == protocol.InitialPathID, pass it", pathID)
			continue pathLoop
		}

		//zzh: return nil if all paths are limited by cwnd
		allCwndLimited = allCwndLimited && (!hasRetransmission && !pth.SendingAllowed())

		// currentRTT = pth.rttStats.SmoothedRTT() //zzh: if SmoothedRTT == 0, send on it. Because it will be duplicated to other paths. TODO maybe not?
		// currentArrivalTime, _ = sch.calculateArrivalTime(s, pth, false)
		currentArrivalTime, _ = sch.calculateArrivalTime(s, pth, false)
		// currentArrivalTime = pth.rttStats.SmoothedRTT()

		// Prefer staying single-path if not blocked by current path
		// Don't consider this sample if the smoothed RTT is 0
		if lowerArrivalTime != 0 && currentArrivalTime == 0 {
			continue pathLoop
		}

		// Case if we have multiple paths unprobed
		//zzh: currentArrivalTime == 0 means rtt == 0
		if currentArrivalTime == 0 {
			currentQuota, ok := sch.quotas[pathID]
			if !ok {
				sch.quotas[pathID] = 0
				currentQuota = 0
			}
			lowerQuota, _ := sch.quotas[selectedPathID]
			utils.Debugf("zzh: pathID %v, currentArrivalTime 0, currentQuota %v, selectedPathID %v, lowerQuota %v", pathID, currentQuota, selectedPathID, lowerQuota)
			if selectedPath != nil && currentQuota > lowerQuota {
				continue pathLoop
			}
		}

		if currentArrivalTime != 0 && lowerArrivalTime != 0 && selectedPath != nil && currentArrivalTime >= lowerArrivalTime { //zzh: right?
			continue pathLoop
		}

		// Update
		lowerArrivalTime = currentArrivalTime
		selectedPath = pth
		selectedPathID = pathID
	}
	if allCwndLimited {
		utils.Debugf("zzh: All paths are cwnd limited, block scheduling, return nil\n")
		return nil
	}

	s.scheduler.previoussendtime = lowerArrivalTime

	return selectedPath //zy changes
	/*
		 zy already return
			var currestNode *node
			if s.streamScheduler.toSend == nil {
				utils.Debugf("zzh: s.streamScheduler.toSend == nil\n")
				currestNode = s.streamScheduler.wrrSchedule() //zzh: stupified!
				s.streamScheduler.toSend = currestNode
			} else {
				utils.Debugf("zzh: s.streamScheduler.toSend != nil\n")
				currestNode = s.streamScheduler.toSend
			}
			//zzh: TODO maybe some more checks
			if currestNode == nil {
				utils.Debugf("zzh: currestStream == nil, seems to be crypto stream 1, find a minrtt path\n")
				return selectedPath
			}
			currestStream := currestNode.stream
			// if currestStream.lenOfDataForWriting() == 0 {
			// 	utils.Debugf("zzh: Stream %d has no data for writing\n", currestStream.streamID)
			// 	// return nil
			// }

			//zzh: case that the stream was previously sent on another path
			previousPathID, ok := sch.previousPath[currestStream.streamID]
			previousPath := s.paths[previousPathID]
			if ok && selectedPathID != previousPathID && previousPath != nil && selectedPath != nil {
				arrivalTimeOnPreviousPath, _ := sch.calculateArrivalTime(s, previousPath, false)
				currentArrivalTimeaddMeanDeviation, _ := sch.calculateArrivalTime(s, selectedPath, true)
				if arrivalTimeOnPreviousPath < currentArrivalTimeaddMeanDeviation {
					utils.Debugf("zzh: current path%d -> previous path%d because of rtt jitter\n", selectedPathID, previousPath.pathID)
					utils.Debugf("zzh: arrivalTimeOnPreviousPath %v, currentArrivalTimeaddMeanDeviation %v\n", arrivalTimeOnPreviousPath, currentArrivalTimeaddMeanDeviation)
					selectedPath = previousPath
				}
			}

			utils.Debugf("zzh: selectedPathID %v sendingallow == %v\n", selectedPath.pathID, selectedPath.SendingAllowed())
			sch.previousPath[currestStream.streamID] = selectedPath.pathID
			return selectedPath
	*/
}

func (sch *scheduler) queueFrames(frames []wire.Frame, pth *path) {
	if sch.packetsNotSentYet[pth.pathID] == nil {
		sch.packetsNotSentYet[pth.pathID] = &PacketList{
			queue:    make([]*packedFrames, 0),
			len:      0,
			toPathid: pth.pathID,
		}
	}
	packetList := sch.packetsNotSentYet[pth.pathID]
	packetList.queue = append(packetList.queue, &packedFrames{frames, time.Now()})
	packetList.len += 1

	utils.Debugf("zzh: queueFrames in path %d, total len %v len(list.queue) %v\n", pth.pathID, packetList.len, len(packetList.queue))
}

func (sch *scheduler) dequeueStoredFrames(pth *path) []wire.Frame {
	//TODO
	packetList := sch.packetsNotSentYet[pth.pathID]
	if len(packetList.queue) == 0 {
		return nil
	}
	packet := packetList.queue[0]
	// Shift the slice and don't retain anything that isn't needed.
	copy(packetList.queue, packetList.queue[1:])
	packetList.queue[len(packetList.queue)-1] = nil
	packetList.queue = packetList.queue[:len(packetList.queue)-1]
	// Update statistics
	packetList.len -= 1
	utils.Debugf("zzh: dequeueStoredFrames in path %d, total len %v len(list.queue) %v \n", pth.pathID, packetList.len, len(packetList.queue))
	utils.Debugf("zzh: this frame is queued for %v \n", time.Now().Sub(packet.queueTime))
	return packet.frames
}

func (sch *scheduler) sendingQueueEmpty(pth *path) bool {
	if sch.packetsNotSentYet[pth.pathID] == nil {
		sch.packetsNotSentYet[pth.pathID] = &PacketList{
			queue:    make([]*packedFrames, 0),
			len:      0,
			toPathid: pth.pathID,
		}
	}
	return len(sch.packetsNotSentYet[pth.pathID].queue) == 0
}

func (sch *scheduler) allSendingQueueEmpty() bool {

	for _, list := range sch.packetsNotSentYet {
		if len(list.queue) != 0 {
			return false
		}
	}
	utils.Debugf("zzh: allSendingQueueEmpty\n")
	return true
}

func (sch *scheduler) dequeueStoredFramesFromOthers(pth *path) []wire.Frame {
	//TODO
	for pathID, list := range sch.packetsNotSentYet {
		if len(list.queue) != 0 {
			return sch.dequeueStoredFrames(pth.sess.paths[pathID])
		}
	}
	return nil
}

func (sch *scheduler) calculateArrivalTime(s *session, pth *path, addMeanDeviation bool) (time.Duration, bool) {

	packetSize := protocol.MaxPacketSize * 8               //bit uint64
	pthBwd := congestion.Bandwidth(pth.GetPathBandwidth()) // bit per second uint64
	utils.Debugf("zzh: GetPathBandwidth() path %v bwd %v mbps", pth.pathID, pthBwd/1e6)
	inSecond := uint64(time.Second)
	var rtt time.Duration
	if addMeanDeviation {
		rtt = pth.rttStats.SmoothedRTT() + pth.rttStats.MeanDeviation()
		utils.Debugf("zzh: addMeanDeviation path %d, rtt = rtt%v + MD%v", pth.pathID, pth.rttStats.SmoothedRTT(), pth.rttStats.MeanDeviation())
	} else {
		rtt = pth.rttStats.SmoothedRTT()

	}
	if pthBwd == 0 {
		utils.Debugf("zzh: bandwidth of path %v is nil, arrivalTime == rtt/2 %v \n", pth.pathID, rtt/2)
		return rtt / 2, false
	}
	if rtt == 0 {
		utils.Debugf("zzh: rtt of path%d is nil, arrivalTime == 0\n", pth.pathID)
		return 0, true
	}
	writeQueue, ok := sch.packetsNotSentYet[pth.pathID]
	var writeQueueSize protocol.ByteCount
	if !ok {
		writeQueueSize = 0
	} else {
		writeQueueSize = protocol.ByteCount(writeQueue.len) * protocol.DefaultTCPMSS * 8 //in bit
		//protocol.DefaultTCPMSS MaxPacketSize
	}

	arrivalTime := (uint64(packetSize+writeQueueSize)*inSecond)/uint64(pthBwd) + uint64(rtt)/2 //in nanosecond
	utils.Debugf("zzh: arrivalTime of path %d is %v ms writeQueueSize %v bytes, pthBwd %v byte p s, rtt %v\n", pth.pathID, time.Duration(arrivalTime), writeQueueSize/8, pthBwd/8, rtt)
	return time.Duration(arrivalTime), true
}

// Lock of s.paths must be free (in case of log print)
// zzh: we now choose a path to sent, but not
func (sch *scheduler) performPacketSendingOfMine(s *session, windowUpdateFrames []*wire.WindowUpdateFrame, pth *path) (*ackhandler.Packet, bool, error) {
	utils.Debugf("zzh: performPacketSendingOfMine() IN")
	defer utils.Debugf("zzh: performPacketSendingOfMine() OUT")

	var err error
	var packet *packedPacket
	if pth.sentPacketHandler.ShouldSendRetransmittablePacket() {
		s.packer.QueueControlFrame(&wire.PingFrame{}, pth)
	}
	//zzh START

	if pth.SendingAllowed() && sch.sendingQueueEmpty(pth) { //normally
		// packet, err = s.packer.PackPacket(s, pth)
		packet, err = s.packer.PackPacket(pth) // zzh: don't need session, because we only have path not stream
		s.exceed_deadline.Set(false)
		utils.Debugf("zzh: PackPacket()")
		if err != nil || packet == nil {
			return nil, false, err
		}
	} else if !pth.SendingAllowed() {
		stored, err := s.packer.StoreFrames(s, pth) //zzh //zzh: don't need session, because we only have path not stream
		utils.Debugf("zzh: path %v, !SendingAllowed() Stored!", pth.pathID)
		if stored {
			return nil, true, err //zzh: here the "sent" bool is set to true, then the loop outside will not break
		} else {
			return nil, false, err //zzh: here the "sent" bool is set to true, then the loop outside will not break
		}
	} else {
		packet, err = s.packer.PackPacketWithStoreFrames(pth)
		s.exceed_deadline.Set(false)
		utils.Debugf("zzh: PackPacketWithStoreFrames() path %v", pth.pathID)
		if err != nil || packet == nil {
			return nil, false, err
		}
	}
	//zzh END

	// packet, err = s.packer.PackPacket(pth)
	// if err != nil || packet == nil {
	// 	return nil, false, err
	// }
	// original code

	if err = s.sendPackedPacket(packet, pth); err != nil {
		return nil, false, err
	}
	packets, retransmissions, losses := pth.sentPacketHandler.GetStatistics()
	utils.Debugf("zzh: after sendPackedPacket() path %v, packets %v retransmissions %v, losses %v", pth.pathID, packets, retransmissions, losses)

	// send every window update twice
	for _, f := range windowUpdateFrames {
		s.packer.QueueControlFrame(f, pth)
	}

	// Packet sent, so update its quota
	sch.quotas[pth.pathID]++

	// Provide some logging if it is the last packet
	for _, frame := range packet.frames {
		switch frame := frame.(type) {
		case *wire.StreamFrame:
			if frame.FinBit {
				// Last packet to send on the stream, print stats
				s.pathsLock.RLock()
				utils.Infof("Info for stream %x of %x", frame.StreamID, s.connectionID)
				for pathID, pth := range s.paths {
					sntPkts, sntRetrans, sntLost := pth.sentPacketHandler.GetStatistics()
					rcvPkts := pth.receivedPacketHandler.GetStatistics()
					utils.Infof("Path %x: sent %d retrans %d lost %d; rcv %d rtt %v", pathID, sntPkts, sntRetrans, sntLost, rcvPkts, pth.rttStats.SmoothedRTT())
				}
				s.pathsLock.RUnlock()
			}
		default:
		}
	}

	pkt := &ackhandler.Packet{
		PacketNumber:    packet.number,
		Frames:          packet.frames,
		Length:          protocol.ByteCount(len(packet.raw)),
		EncryptionLevel: packet.encryptionLevel,
	}

	utils.Debugf("zzh: Finally send pkt %v on path %v", pkt.PacketNumber, pth.pathID)
	return pkt, true, nil
}

func (sch *scheduler) calculateArrivalTimefromsendbuffer(sess *session, pth *path, addMeanDeviation bool) (arrivalTime time.Duration, ok bool) {
	if pth == nil {
		ok = false
		return
	}
	fn := func(s *stream) (bool, error) {
		packetSize := protocol.MaxPacketSize * 8               //bit uint64
		pthBwd := congestion.Bandwidth(pth.GetPathBandwidth()) // bit per second uint64
		utils.Debugf("zzh: GetPathBandwidth() path %v bwd %v mbps", pth.pathID, pthBwd/1e6)
		inSecond := uint64(time.Second)
		var rtt time.Duration
		if addMeanDeviation {
			rtt = pth.rttStats.SmoothedRTT() + pth.rttStats.MeanDeviation()
			utils.Debugf("zzh: addMeanDeviation path %d, rtt = rtt%v + MD%v", pth.pathID, pth.rttStats.SmoothedRTT(), pth.rttStats.MeanDeviation())
		} else {
			rtt = pth.rttStats.SmoothedRTT()

		}
		if pthBwd == 0 {
			utils.Debugf("zzh: bandwidth of path %v is nil, arrivalTime == rtt/2 %v \n", pth.pathID, rtt/2)
			if (rtt / 2) > arrivalTime {
				arrivalTime = rtt / 2
				ok = false
			}
			return false, nil
		}
		if rtt == 0 {
			utils.Debugf("zzh: rtt of path%d is nil, arrivalTime == 0\n", pth.pathID)
			if (rtt) > arrivalTime {
				arrivalTime = rtt
				ok = true
			}
			return true, nil
		}
		writeQueue := s.lenOfDataForWriting()
		var writeQueueSize protocol.ByteCount
		if writeQueue == 0 {
			writeQueueSize = 0
		} else {
			writeQueueSize = writeQueue * protocol.DefaultTCPMSS * 8 //in bit
			//protocol.DefaultTCPMSS MaxPacketSize
		}

		arrivalTime1 := (uint64(packetSize+writeQueueSize)*inSecond)/uint64(pthBwd) + uint64(rtt)/2 + uint64(sch.previoussendtime) //in nanosecond
		if time.Duration(arrivalTime1) > arrivalTime || arrivalTime == 0 {
			arrivalTime = time.Duration(arrivalTime1)
		}
		ok = true
		utils.Debugf("zzh: arrivalTime of path %d is %v ms writeQueueSize %v bytes, pthBwd %v byte p s, rtt %v\n", pth.pathID, time.Duration(arrivalTime), writeQueueSize/8, pthBwd/8, rtt)
		return true, nil
	}

	sess.streamsMap.RoundRobinIterate(fn)

	return
}
