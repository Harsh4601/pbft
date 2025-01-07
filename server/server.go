package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math"
	// "math"
	"net"
	"net/rpc"
	"os"
	// "sort"
	"sync"
	"time"
)

func init() {
	gob.Register(Transaction{})
	gob.Register(Server{})

}

var serverPublicKeyMap = make(map[int]*rsa.PublicKey)

type TransactionMessage struct {
	Transaction Transaction
	Timestamp   int64
	ClientName  string
	Signature   string
	PublicKey   string
}

type Message struct {
	Transaction Transaction
	Timestamp   int64
	ClientName  string
	Signature   string
	PublicKey   string
}

type PrePrepareMessage struct {
	View        int
	SequenceNum int
	Digest      string
	Transaction Transaction
	ClientName  string
	Signature   string
	SenderID    int
	Timestamp   int64
}

type ViewChangeMessage struct {
	ViewNumber               int
	ServerID                 int
	PendingMessageCollection []Message
}

type PrepareMessage struct {
	ViewNumber  int
	SequenceNum int
	Digest      string
	ServerID    int
	Signature   string
	PublicKey   *rsa.PublicKey
	Transaction Transaction
}

type Transaction struct {
	Sender   string
	Receiver string
	Amount   int
}

type NetworkStatus struct {
	ActiveServers    map[string]bool
	ByzantineServers map[string]bool
}

type Server struct {
	Name                     string
	Port                     string
	ServerID                 int
	Balances                 map[string]int
	BalanceLock              sync.Mutex
	ActiveServers            map[string]bool
	ByzantineServers         map[string]bool
	DataStore                [][]Transaction
	Mutex                    sync.Mutex
	SequenceNumber           int
	SequenceNumberLock       sync.Mutex
	LastCommittedSequenceNum int
	CurrentView              int
	TransactionLog           []Transaction
	PrivateKey               *rsa.PrivateKey
	PublicKey                *rsa.PublicKey
	PrePrepareLog            map[int]PrePrepareMessage
	PrepareLog               map[int][]PrepareMessage
	CommitLog                map[int][]CommitMessage
	ProcessedCommits         map[int]bool
	ProcessedCommitsLock     sync.Mutex
	ProcessedPrepares        map[int]bool
	ProcessedPreparesLock    sync.Mutex
	ViewChangeLock           sync.Mutex
	ViewChangeOngoing        bool
	Timer                    *time.Timer
	TimerDuration            time.Duration
	LastExecutedSequenceNum  int
	ExecutionLock            sync.Mutex
	ExecutionBuffer          map[int]CommitCertificate
	SequenceStatus           map[int]string
	SequenceStatusLock       sync.RWMutex
	QuorumReached            bool
	PendingMessageCollection []Message
	ViewChangeMsgCount       map[int]int
	ViewChangeCompleted      map[int]bool
	ViewChangeMsgMutex       sync.Mutex
	latency                  time.Duration
	txn_executed             int
}

type PreparedCertificate struct {
	ViewNumber  int
	SequenceNum int
	Digest      string
	Signatures  map[int]string
	SenderID    int
	Transaction Transaction
}

type CommitCertificate struct {
	ViewNumber  int
	SequenceNum int
	Digest      string
	Signatures  map[int]string
	SenderID    int
	Transaction Transaction
}

type Args struct {
	Transaction Transaction
}

type PublicKeyMessage struct {
	ServerID  int
	PublicKey *rsa.PublicKey
}

type CommitMessage struct {
	ViewNumber  int
	SequenceNum int
	Digest      string
	ServerID    int
	Transaction Transaction
	Signature   string
}

func parsePublicKey(pemEncodedPubKey string) (*rsa.PublicKey, error) {

	block, _ := pem.Decode([]byte(pemEncodedPubKey))
	if block == nil {

		return nil, errors.New("failed to decode PEM block containing public key")
	}

	if block.Type != "RSA PUBLIC KEY" {

		return nil, errors.New("decoded block is not of type RSA PUBLIC KEY")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {

		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {

		return nil, errors.New("not an RSA public key")
	}

	return rsaPub, nil
}

func verifySignature(publicKey *rsa.PublicKey, message []byte, signature string) error {

	hashed := sha256.Sum256(message)

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {

		return err
	}

	err = rsa.VerifyPKCS1v15(publicKey, 0, hashed[:], signatureBytes)
	if err != nil {

		return fmt.Errorf("verification failed: %v", err)
	}

	// log.Println("Signature successfully verified")
	return nil
}

func (s *Server) initializeTimer() {
	s.TimerDuration = 3 * time.Second
	s.resetTimer()
}

func (s *Server) resetTimer() {
	if s.Timer != nil {
		s.Timer.Stop()
	}
	s.Timer = time.AfterFunc(s.TimerDuration, func() {
		s.handleTimeout()
	})
}

func (s *Server) handleTimeout() {

	s.ViewChangeLock.Lock()
	defer s.ViewChangeLock.Unlock()

	if s.ViewChangeOngoing {
		// View change already in progress
		return
	}

	s.ViewChangeOngoing = true
	log.Printf("Server %d: Timeout occurred, initiating view change to view %d", s.ServerID, s.CurrentView+1)

	s.initiateViewChange(s.PendingMessageCollection)

}

func (s *Server) initiateViewChange(pendingMsg []Message) {

	s.CurrentView += 1
	s.ViewChangeOngoing = true

	viewChangeMsg := ViewChangeMessage{
		ViewNumber:               s.CurrentView,
		ServerID:                 s.ServerID,
		PendingMessageCollection: pendingMsg,
	}

	s.broadcastViewChange(viewChangeMsg)

}

func (s *Server) broadcastViewChange(viewChangeMsg ViewChangeMessage) {

	for id := 1; id <= 7; id++ {
		if id != s.ServerID {

			addr := fmt.Sprintf("localhost:800%d", id)
			client, err := rpc.Dial("tcp", addr)
			if err != nil {
				fmt.Printf("Error connecting to server %d: %v\n", id, err)

			}
			defer client.Close()

			var response string
			err = client.Call("Server.HandleViewChange", viewChangeMsg, &response)
			if err != nil {
				fmt.Printf("Error sending preprepare message to server %d: %v\n", id, err)
			}
		}
	}
}

func (s *Server) HandleViewChange(viewChangeMsg ViewChangeMessage, reply *string) error {

	log.Printf("NEW VIEW NUMBER: %+v", viewChangeMsg.ViewNumber)

	primary := s.getPrimaryID(viewChangeMsg.ViewNumber)

	s.ViewChangeMsgMutex.Lock()
	defer s.ViewChangeMsgMutex.Unlock()

	s.ViewChangeMsgCount[viewChangeMsg.ViewNumber]++
	receivedCount := s.ViewChangeMsgCount[viewChangeMsg.ViewNumber]
	f := 2
	quorumSize := 2 * f

	if s.ViewChangeCompleted[viewChangeMsg.ViewNumber] {
		return nil
	}

	if receivedCount >= quorumSize {
		s.ViewChangeCompleted[viewChangeMsg.ViewNumber] = true
	}

	if s.ServerID == primary {

		log.Printf("I AM THE NEW PRIMARY")

		if receivedCount >= quorumSize {
			log.Printf("QUORUM RECHED FOR NEW VIEW %d. MOVING TO NEW VIEW.", viewChangeMsg.ViewNumber)
			log.Printf("PENDING MESAGES: %+v", viewChangeMsg.PendingMessageCollection)
			s.newView(viewChangeMsg)
			
		}
	}

	return nil
}

func (s *Server) newView(viewChangeMsg ViewChangeMessage) {

	s.CurrentView = viewChangeMsg.ViewNumber
	s.ViewChangeOngoing = false

	log.Printf("PENDING MESAGES: %+v", viewChangeMsg.PendingMessageCollection)
	log.Printf("Server %d has moved to the new view %d", s.ServerID, s.CurrentView)

	for _, msg := range viewChangeMsg.PendingMessageCollection {
		var reply string
		err := s.HandleTransaction(msg, &reply)
		if err != nil {
			log.Printf("Error processing transaction in new view: %v", err)
		}
	}
}

func (s *Server) startServer() {

	rpc.Register(s)

	ln, err := net.Listen("tcp", ":"+s.Port)
	if err != nil {
		log.Fatalf("Error starting the server %s on port %s: %v\n", s.Name, s.Port, err)
	}
	defer ln.Close()
	fmt.Printf("%s server running on port %s\n", s.Name, s.Port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		go rpc.ServeConn(conn)
	}
}

func (s *Server) updateSequenceStatus(seqNum int, status string) {

	s.SequenceStatusLock.Lock()
	defer s.SequenceStatusLock.Unlock()

	if _, exists := s.SequenceStatus[seqNum]; !exists {
		s.SequenceStatus[seqNum] = "X"
		// log.Printf("Server %d: Sequence %d initialized to status X", s.ServerID, seqNum)
	}

	s.SequenceStatus[seqNum] = status
	// log.Printf("Server %d: Sequence %d updated to status %s", s.ServerID, seqNum, status)
	// log.Printf("Current status of Sequence %d: %s", seqNum, s.SequenceStatus[seqNum])

}

func (s *Server) HandleNetworkStatus(networkStatus NetworkStatus, reply *string) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	s.ActiveServers = networkStatus.ActiveServers
	s.ByzantineServers = networkStatus.ByzantineServers

	log.Printf("UPDATED NETWORK STATUS: ActiveServers: %v, ByzantineServers: %v", s.ActiveServers, s.ByzantineServers)

	return nil
}

func (s *Server) getNextSequenceNumber() int {
	s.SequenceNumberLock.Lock()
	defer s.SequenceNumberLock.Unlock()
	s.SequenceNumber++
	return s.SequenceNumber
}

func (s *Server) getPrimaryID(viewNumber int) int {
	n := 7
	return (viewNumber % n) + 1
}

func (s *Server) HandleClientRequest(msg Message, reply *string) error {

	time_start := time.Now()

	log.Printf("Server %d: Received client request from %s SENDER: %s RECEIVER %s", s.ServerID, msg.ClientName, msg.Transaction.Sender, msg.Transaction.Receiver)

	time.Sleep(20 * time.Millisecond)

	s.PendingMessageCollection = append(s.PendingMessageCollection, msg)

	primaryID := s.getPrimaryID(s.CurrentView)

	if s.ServerID == primaryID {
		s.HandleTransaction(msg, reply)
	} else {
		log.Printf("I AM REPLICA, STARTING TIMER!!!!")
		s.initializeTimer()
	}

	s.latency += time.Since(time_start)
	s.txn_executed++

	return nil
}

func (s *Server) HandleTransaction(msg Message, reply *string) error {

	// time_start := time.Now()

	if s.ByzantineServers[s.Name] {
		log.Printf("PRIMARY SERVER IS BYZANTINE!!!")
		return nil
	}

	log.Printf("ENTERED HANDLE TRANSACTION FUNCTION BY PRIMARY SERVER")

	publicKey, err := parsePublicKey(msg.PublicKey)

	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	messageContent := fmt.Sprintf("%s:%s:%d:%d:%s",
		msg.Transaction.Sender,
		msg.Transaction.Receiver,
		msg.Transaction.Amount,
		msg.Timestamp,
		msg.ClientName,
	)

	err = verifySignature(publicKey, []byte(messageContent), msg.Signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}

	sequenceNumber := s.getNextSequenceNumber()

	digest := sha256.Sum256([]byte(messageContent))
	digestStr := fmt.Sprintf("%x", digest)

	prePrepareMsg := PrePrepareMessage{
		View:        s.CurrentView,
		SequenceNum: sequenceNumber,
		Digest:      digestStr,
		Transaction: msg.Transaction,
		ClientName:  msg.ClientName,
		Timestamp:   msg.Timestamp,
		SenderID:    s.ServerID,
	}

	if s.SequenceStatus[prePrepareMsg.SequenceNum] != "E" {
		s.updateSequenceStatus(prePrepareMsg.SequenceNum, "PP")
	}

	log.Printf("PREPREPARE MESSAGE TRANSACTION SENDER: %s RECEIVER: %s SEQUENCE NUMBER%d", prePrepareMsg.Transaction.Sender, prePrepareMsg.Transaction.Receiver, prePrepareMsg.SequenceNum)

	err = s.broadcastPrePrepare(prePrepareMsg)
	if err != nil {
		return fmt.Errorf("failed to broadcast pre-prepare message: %v", err)
	}

	// s.latency += time.Since(time_start)
	// s.txn_executed++

	return nil
}

func (s *Server) broadcastPrePrepare(prePrepareMsg PrePrepareMessage) error {

	for id := 1; id <= 7; id++ {
		if id != s.ServerID {

			addr := fmt.Sprintf("localhost:800%d", id)
			client, err := rpc.Dial("tcp", addr)
			if err != nil {
				fmt.Printf("Error connecting to server %d: %v\n", id, err)
				return nil
			}
			defer client.Close()

			var response string
			err = client.Call("Server.HandlePrePrepare", &prePrepareMsg, &response)
			if err != nil {
				fmt.Printf("Error sending preprepare message to server %d: %v\n", id, err)
			}
		}
	}

	return nil
}

func (s *Server) HandlePrePrepare(prePrepareMsg PrePrepareMessage, reply *string) error {

	// log.Printf("Received pre-prepare message from primary: %+v", prePrepareMsg)

	if s.ByzantineServers[s.Name] {
		log.Printf("I AM BYZANTINE")
		s.updateSequenceStatus(prePrepareMsg.SequenceNum, "PP")
		if s.Timer != nil {
			s.Timer.Stop()
		}
		return nil
	}

	if !s.ActiveServers[s.Name] {
		log.Printf("I AM INACTIVE")
		if s.Timer != nil {
			s.Timer.Stop()
		}
		return nil
	}

	messageContent := fmt.Sprintf("%s:%s:%d:%d:%s",
		prePrepareMsg.Transaction.Sender,
		prePrepareMsg.Transaction.Receiver,
		prePrepareMsg.Transaction.Amount,
		prePrepareMsg.Timestamp,
		prePrepareMsg.ClientName,
	)

	digest := sha256.Sum256([]byte(messageContent))
	digestStr := fmt.Sprintf("%x", digest)

	if digestStr != prePrepareMsg.Digest {
		return fmt.Errorf("digest mismatch, message might be altered")
	}

	log.Println("Pre-prepare message verified successfully")
	if s.SequenceStatus[prePrepareMsg.SequenceNum] != "E" {
		s.updateSequenceStatus(prePrepareMsg.SequenceNum, "PP")
	}

	// log.Printf("STOPPING TIMER!!!")

	if s.Timer != nil {
		s.Timer.Stop()
	}

	s.Mutex.Lock()
	s.PrePrepareLog[prePrepareMsg.SequenceNum] = prePrepareMsg

	s.Mutex.Unlock()

	err := s.sendPrepareMessage(prePrepareMsg.View, prePrepareMsg.SequenceNum, digestStr, prePrepareMsg.Transaction, prePrepareMsg.SenderID)
	if err != nil {
		return fmt.Errorf("failed to send prepare message: %v", err)
	}

	return nil
}

func signMessage(privateKey *rsa.PrivateKey, message []byte) (string, error) {
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, 0, hashed[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %v", err)
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (s *Server) sendPrepareMessage(viewNumber, sequenceNum int, digest string, transaction Transaction, senderID int) error {

	if s.ByzantineServers[s.Name] {
		return nil
	}

	if !s.ActiveServers[s.Name] {
		return nil
	}

	messageContent := fmt.Sprintf("%d:%d:%s:%d", viewNumber, sequenceNum, digest, s.ServerID)

	signature, err := signMessage(s.PrivateKey, []byte(messageContent))
	if err != nil {
		return fmt.Errorf("failed to sign prepare message: %v", err)
	}

	prepareMsg := PrepareMessage{
		ViewNumber:  viewNumber,
		SequenceNum: sequenceNum,
		Digest:      digest,
		ServerID:    s.ServerID,
		Signature:   signature,
		PublicKey:   s.PublicKey,
		Transaction: transaction,
	}

	addr := fmt.Sprintf("localhost:800%d", senderID)
	client, err := rpc.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("error connecting to primary server: %v", err)
	}
	defer client.Close()

	var reply string
	err = client.Call("Server.HandlePrepare", prepareMsg, &reply)
	if err != nil {
		return fmt.Errorf("error calling remote procedure: %v", err)
	}

	return nil
}

func (s *Server) HandlePrepare(prepareMsg PrepareMessage, reply *string) error {

	messageContent := fmt.Sprintf("%d:%d:%s:%d", prepareMsg.ViewNumber, prepareMsg.SequenceNum, prepareMsg.Digest, prepareMsg.ServerID)

	err := verifySignature(prepareMsg.PublicKey, []byte(messageContent), prepareMsg.Signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}

	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	s.PrepareLog[prepareMsg.SequenceNum] = append(s.PrepareLog[prepareMsg.SequenceNum], prepareMsg)

	f := 2
	quorumSize := 2 * f

	if len(s.PrepareLog[prepareMsg.SequenceNum]) >= quorumSize {

		s.ProcessedPreparesLock.Lock()
		if s.ProcessedPrepares[prepareMsg.SequenceNum] {
			s.ProcessedPreparesLock.Unlock()
			return nil
		}

		if s.SequenceStatus[prepareMsg.SequenceNum] != "E" {
			s.updateSequenceStatus(prepareMsg.SequenceNum, "P")
		}

		s.ProcessedPrepares[prepareMsg.SequenceNum] = true
		s.ProcessedPreparesLock.Unlock()

		log.Printf("Quorum reached for prepare message! on sequence number %d!", prepareMsg.SequenceNum)

		preparedCertificate := PreparedCertificate{
			ViewNumber:  prepareMsg.ViewNumber,
			SequenceNum: prepareMsg.SequenceNum,
			Digest:      prepareMsg.Digest,
			Signatures:  make(map[int]string),
			SenderID:    s.ServerID,
			Transaction: prepareMsg.Transaction,
		}

		for _, msg := range s.PrepareLog[prepareMsg.SequenceNum] {
			preparedCertificate.Signatures[msg.ServerID] = msg.Signature
		}

		// log.Printf("Certificate created and broadcasted to other replicas")

		s.broadcastPreparedCertificate(preparedCertificate)

	} else {
		log.Printf("Quorum not reached for prepare message for sequence number %d!", prepareMsg.SequenceNum)
		s.QuorumReached = false

		if !s.QuorumReached {
			s.broadcastQuorum(prepareMsg.SequenceNum)
		}
	}

	return nil
}

func (s *Server) broadcastQuorum(seqNum int) {

	for id := 1; id <= 7; id++ {

		addr := fmt.Sprintf("localhost:800%d", id)
		client, err := rpc.Dial("tcp", addr)
		if err != nil {
			fmt.Printf("Error connecting to server %d: %v\n", id, err)
		}
		defer client.Close()

		var response string
		err = client.Call("Server.HandleQuorumNotReached", seqNum, &response)
		if err != nil {
			fmt.Printf("Error sending preprepare message to server %d: %v\n", id, err)
		}
	}

}

func (s *Server) HandleQuorumNotReached(seqNum int, reply *string) error {

	s.QuorumReached = false
	s.updateSequenceStatus(seqNum, "PP")

	return nil
}

func (s *Server) broadcastPreparedCertificate(preparedCertificate PreparedCertificate) error {

	for id := 1; id <= 7; id++ {
		if id != s.ServerID {

			addr := fmt.Sprintf("localhost:800%d", id)
			client, err := rpc.Dial("tcp", addr)
			if err != nil {
				fmt.Printf("Error connecting to server %d: %v\n", id, err)
				return nil
			}
			defer client.Close()

			var response string
			err = client.Call("Server.HandlePrepareCertificate", &preparedCertificate, &response)
			if err != nil {
				fmt.Printf("Error sending preprepare message to server %d: %v\n", id, err)
			}
		}
	}

	return nil
}

func (s *Server) HandlePrepareCertificate(preparedCertificate PreparedCertificate, reply *string) error {

	if s.ByzantineServers[s.Name] {
		return nil
	}

	if !s.ActiveServers[s.Name] {
		return nil
	}

	// log.Printf("Received prepare certificate for sequence number: %d from server: %d", preparedCertificate.SequenceNum, preparedCertificate.SenderID)

	if s.SequenceStatus[preparedCertificate.SequenceNum] != "E" {
		s.updateSequenceStatus(preparedCertificate.SequenceNum, "P")

	}

	commitMsg := CommitMessage{
		ViewNumber:  preparedCertificate.ViewNumber,
		SequenceNum: preparedCertificate.SequenceNum,
		Digest:      preparedCertificate.Digest,
		ServerID:    s.ServerID,
		Transaction: preparedCertificate.Transaction,
	}

	s.LastCommittedSequenceNum = commitMsg.SequenceNum // changing lastcommittedsequence number for replicas

	addr := fmt.Sprintf("localhost:800%d", preparedCertificate.SenderID)
	client, err := rpc.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("error connecting to primary server: %v", err)
	}
	defer client.Close()

	var commitReply string
	err = client.Call("Server.HandleCommit", commitMsg, &commitReply)
	if err != nil {
		return fmt.Errorf("error sending commit message to primary server: %v", err)
	}

	log.Printf("Commit message sent to primary server %s, reply: %s\n", addr, commitReply)

	return nil
}

func (s *Server) HandleCommit(commitMsg CommitMessage, reply *string) error {

	// log.Printf("Received commit message from server %d for sequence number %d SENDER: %s RECEIVER %s\n", commitMsg.ServerID, commitMsg.SequenceNum, commitMsg.Transaction.Sender, commitMsg.Transaction.Receiver)

	s.CommitLog[commitMsg.SequenceNum] = append(s.CommitLog[commitMsg.SequenceNum], commitMsg)

	f := 2
	quorumSize := 2 * f

	if len(s.CommitLog[commitMsg.SequenceNum]) >= quorumSize {

		s.ProcessedCommitsLock.Lock()
		if s.ProcessedCommits[commitMsg.SequenceNum] {
			s.ProcessedCommitsLock.Unlock()
			return nil
		}

		s.ProcessedCommits[commitMsg.SequenceNum] = true
		s.ProcessedCommitsLock.Unlock()

		// time.Sleep(100 * time.Millisecond)
		if s.SequenceStatus[commitMsg.SequenceNum] != "E" {
			s.updateSequenceStatus(commitMsg.SequenceNum, "C")
		}

		log.Printf("Quorum reached for commit messages on sequence number %d!", commitMsg.SequenceNum)

		commitCertificate := CommitCertificate{
			ViewNumber:  commitMsg.ViewNumber,
			SequenceNum: commitMsg.SequenceNum,
			Digest:      commitMsg.Digest,
			Signatures:  make(map[int]string),
			SenderID:    s.ServerID,
			Transaction: commitMsg.Transaction,
		}

		s.LastCommittedSequenceNum = commitMsg.SequenceNum // changing lastcommittedsequence number for primary

		for _, msg := range s.CommitLog[commitMsg.SequenceNum] {
			commitCertificate.Signatures[msg.ServerID] = msg.Signature
		}

		log.Printf("Commit certificate created and broadcasted to other replicas for sequence number %d", commitMsg.SequenceNum)

		s.broadcastCommitCertificate(commitCertificate)

		err := s.GoToCommitPhase(commitCertificate, reply)
		if err != nil {
			log.Printf("Server %d: Failed to execute commit phase locally: %v", s.ServerID, err)
		}

		// log.Printf("Transaction for sequence number %d has been fully committed", commitMsg.SequenceNum)

	} else {
		// log.Printf("Quorum not reached for commit message for sequence number %d!", commitMsg.SequenceNum)
	}
	return nil
}

func (s *Server) broadcastCommitCertificate(commitCertificate CommitCertificate) error {

	for id := 1; id <= 7; id++ {
		if id != s.ServerID {
			addr := fmt.Sprintf("localhost:800%d", id)
			client, err := rpc.Dial("tcp", addr)
			if err != nil {
				fmt.Printf("Error connecting to server %d: %v\n", id, err)
				return nil
			}
			defer client.Close()

			var response string
			err = client.Call("Server.GoToCommitPhase", &commitCertificate, &response)
			if err != nil {
				fmt.Printf("Error sending preprepare message to server %d: %v\n", id, err)
			}
		}
	}

	return nil
}

func (s *Server) GoToCommitPhase(commitCertificate CommitCertificate, reply *string) error {

	// log.Printf("Received commit certificate for sequence number %d from primary server", commitCertificate.SequenceNum)
	// log.Printf("COMMIT CERTIFICATE TRANSACTION RECEVIED: %+v", commitCertificate.Transaction)

	if s.ByzantineServers[s.Name] {
		s.updateSequenceStatus(commitCertificate.SequenceNum, "PP")

	} else if !s.ActiveServers[s.Name] {
		s.updateSequenceStatus(commitCertificate.SequenceNum, "X")
	} else {
		if s.SequenceStatus[commitCertificate.SequenceNum] != "E" {
			s.updateSequenceStatus(commitCertificate.SequenceNum, "C")
		}
	}

	s.ExecutionLock.Lock()
	defer s.ExecutionLock.Unlock()

	expectedSeqNum := s.LastExecutedSequenceNum + 1

	if commitCertificate.SequenceNum == expectedSeqNum {

		s.executeTransaction(commitCertificate)
		s.LastExecutedSequenceNum = commitCertificate.SequenceNum

		s.processBufferedCommits()
	} else if commitCertificate.SequenceNum > expectedSeqNum {
		// log.Printf("Sequence number %d is higher than expected %d. Buffering the commit certificate.", commitCertificate.SequenceNum, expectedSeqNum)
		s.ExecutionBuffer[commitCertificate.SequenceNum] = commitCertificate
	} else {
		// log.Printf("Received commit certificate for sequence number %d which is less than or equal to last executed %d. Ignoring.", commitCertificate.SequenceNum, s.LastExecutedSequenceNum)
	}

	return nil

}

func (s *Server) processBufferedCommits() {
	nextSeqNum := s.LastExecutedSequenceNum + 1

	for {
		commitCert, exists := s.ExecutionBuffer[nextSeqNum]
		if !exists {
			break
		}

		log.Printf("Executing buffered commit certificate for sequence number %d", nextSeqNum)
		s.executeTransaction(commitCert)
		s.LastExecutedSequenceNum = nextSeqNum

		delete(s.ExecutionBuffer, nextSeqNum)

		nextSeqNum++
	}
}

func (s *Server) executeTransaction(commitCertificate CommitCertificate) {

	// start := time.Now()

	s.BalanceLock.Lock()
	defer s.BalanceLock.Unlock()

	if s.ByzantineServers[s.Name] {
		log.Printf("Server %s is Byzantine; skipping execution of transaction %+v", s.Name, commitCertificate.Transaction)
		s.TransactionLog = append(s.TransactionLog, commitCertificate.Transaction)
		// s.displayBalances(commitCertificate.SequenceNum)
		return
	} else if !s.ActiveServers[s.Name] {
		log.Printf("Server %s is Inactive; skipping execution of transaction %+v", s.Name, commitCertificate.Transaction)
		// s.displayBalances(commitCertificate.SequenceNum)
		return
	}

	sender := commitCertificate.Transaction.Sender
	receiver := commitCertificate.Transaction.Receiver
	amount := commitCertificate.Transaction.Amount

	if s.Balances[sender] >= amount {
		s.Balances[sender] -= amount
		s.Balances[receiver] += amount
		log.Printf("Transaction applied: %s sent %d units to %s", sender, amount, receiver)
	} else {
		log.Printf("Insufficient funds: %s tried to send %d units to %s", sender, amount, receiver)
	}

	s.TransactionLog = append(s.TransactionLog, commitCertificate.Transaction)

	s.updateSequenceStatus(commitCertificate.SequenceNum, "E")

	// s.displayBalances(commitCertificate.SequenceNum)

	// elapsed := time.Since(start)
	// s.Mutex.Lock()
	// s.latency += elapsed
	// s.Mutex.Unlock()

}

// func (s *Server) displayBalances(seqNum int) {
// 	log.Printf("Updated balances after sequence number %d:", seqNum)

// 	members := make([]string, 0, len(s.Balances))
// 	for member := range s.Balances {
// 		members = append(members, member)
// 	}

// 	sort.Strings(members)

// 	for _, member := range members {
// 		log.Printf("Member %s: %d units", member, s.Balances[member])
// 	}
// }

func generateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil
	}
	return privKey, &privKey.PublicKey
}

func (s *Server) CheckLog(activeStatus string, reply *[]Transaction) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	*reply = s.TransactionLog
	return nil
}

func (s *Server) CheckBalance(activeStatus string, reply *map[string]int) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	primaryID := s.getPrimaryID(s.CurrentView)
	if s.ServerID == primaryID {

		*reply = s.Balances
	}
	return nil
}

func (s *Server) CheckStatus(sequenceNumber int, reply *string) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	*reply = s.SequenceStatus[sequenceNumber]

	return nil
}

// func (s *Server) SendPerformance(activeStatus string, reply *[]float64) error {
// 	s.Mutex.Lock()
// 	defer s.Mutex.Unlock()

// 	txnExecuted := math.Round(float64(s.txn_executed))
// 	latencyMs := math.Round(s.latency.Seconds())

// 	*reply = []float64{txnExecuted, latencyMs}

// 	return nil
// }

// func (s *Server) SendPerformance(activeStatus string, reply *[]float64) error {
//     s.Mutex.Lock()
//     defer s.Mutex.Unlock()

//     // Ensure txnExecuted is a whole number
//     txnExecuted := math.Round(float64(s.txn_executed))

//     // Calculate latency in seconds with two decimal places
//     latencySeconds := math.Round(s.latency.Seconds()*100) / 100

//     *reply = []float64{txnExecuted, latencySeconds}

//     return nil
// }

func (s *Server) SendPerformance(activeStatus string, reply *[]float64) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	// Convert txnExecuted to an integer
	txnExecuted := float64(int(math.Round(float64(s.txn_executed))))

	// Convert latency to milliseconds with two decimal places
	latencyMs := math.Round(s.latency.Seconds()*1000) / 1000

	*reply = []float64{txnExecuted, latencyMs}

	return nil
}

func main() {

	if len(os.Args) < 3 {
		fmt.Println("Usage: go run server.go <server_name> <port>")
		return
	}

	serverName := os.Args[1]
	port := os.Args[2]

	var serverID int
	switch serverName {
	case "S1":
		serverID = 1
	case "S2":
		serverID = 2
	case "S3":
		serverID = 3
	case "S4":
		serverID = 4
	case "S5":
		serverID = 5
	case "S6":
		serverID = 6
	case "S7":
		serverID = 7
	default:
		log.Fatalf("Invalid server name: %s. Must be one of S1, S2, S3, S4, S5, S6 or S7.", serverName)
		return
	}

	privateKey, publicKey := generateKeyPair(2048)

	server := Server{
		Name:                    serverName,
		Port:                    port,
		ServerID:                serverID,
		PrivateKey:              privateKey,
		PublicKey:               publicKey,
		Balances:                make(map[string]int),
		ProcessedCommits:        make(map[int]bool),
		ProcessedPrepares:       make(map[int]bool),
		PrePrepareLog:           make(map[int]PrePrepareMessage),
		PrepareLog:              make(map[int][]PrepareMessage),
		CommitLog:               make(map[int][]CommitMessage),
		LastExecutedSequenceNum: 0,
		ExecutionBuffer:         make(map[int]CommitCertificate),
		SequenceStatus:          make(map[int]string),
		QuorumReached:           true,
		ViewChangeMsgCount:      make(map[int]int),
		ViewChangeCompleted:     make(map[int]bool),
	}

	server.CurrentView = 0

	members := []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J"}
	for _, member := range members {
		server.Balances[member] = 10
	}

	serverPublicKeyMap[serverID] = publicKey
	server.startServer()
}
