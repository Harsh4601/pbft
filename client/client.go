package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"log"
	"net/rpc"
	"os"
	"sort"
	"strconv"
	"strings"
	// "sync"
	"time"
)

func init() {

	gob.Register(Transaction{})
	gob.Register(Message{})
	gob.Register(NetworkStatus{})

}

type Transaction struct {
	Sender   string
	Receiver string
	Amount   int
}

type Message struct {
	Transaction Transaction
	Timestamp   int64
	ClientName  string
	Signature   string
	PublicKey   string
}

type NetworkStatus struct {
	ActiveServers    map[string]bool
	ByzantineServers map[string]bool
}

func sendCheckLog() {

	server_name := []string{"S1", "S2", "S3", "S4", "S5", "S6", "S7"}
	for _, server := range server_name {

		serverAddr := getServerAddress(server)

		client, err := rpc.Dial("tcp", serverAddr)
		if err != nil {
			log.Fatalf("Error connecting to server: %v", err)
		}
		defer client.Close()

		var reply []Transaction
		err = client.Call("Server.CheckLog", server, &reply) 
		if err != nil {
			log.Fatalf("Error calling remote procedure: %v", err)
		}
		fmt.Printf("Log of Client %s: %v\n", server, reply)
	}
}

func sendCheckBalance() {
    serverName := []string{"S1", "S2", "S3", "S4", "S5", "S6", "S7"}
    allBalances := make(map[string]int)

    for _, server := range serverName {
        serverAddr := getServerAddress(server)
        client, err := rpc.Dial("tcp", serverAddr)
        if err != nil {
            log.Fatalf("Error connecting to server: %v", err)
        }
        defer client.Close()

        var reply map[string]int
        err = client.Call("Server.CheckBalance", server, &reply)
        if err != nil {
            log.Fatalf("Error calling remote procedure: %v", err)
        }

        for clientName, balance := range reply {
            allBalances[clientName] = balance
        }
    }


    clientNames := make([]string, 0, len(allBalances))
    for clientName := range allBalances {
        clientNames = append(clientNames, clientName)
    }
    sort.Strings(clientNames)
    for _, clientName := range clientNames {
        fmt.Printf("Balance of Client %s: %d\n", clientName, allBalances[clientName])
    }
}

func sendPrintStatus() {

    var sequenceNumber int
    fmt.Print("Enter the sequence number: ")
    _, err := fmt.Scanln(&sequenceNumber)
    if err != nil {
        log.Fatalf("Error reading sequence number: %v", err)
    }

    serverName := []string{"S1", "S2", "S3", "S4", "S5", "S6", "S7"}
    for _, server := range serverName {
        serverAddr := getServerAddress(server)

        client, err := rpc.Dial("tcp", serverAddr)
        if err != nil {
            log.Fatalf("Error connecting to server: %v", err)
        }
        defer client.Close()

        var reply string
        err = client.Call("Server.CheckStatus", sequenceNumber, &reply)
        if err != nil {
            log.Fatalf("Error calling remote procedure: %v", err)
        }
        fmt.Printf("Status of Server %s for sequence number %d: %v\n", server, sequenceNumber, reply)
    }
}

func sendPerformance() {
    serverNames := []string{"S1", "S2", "S3", "S4", "S5", "S6", "S7"}

    for _, server := range serverNames {
        serverAddr := getServerAddress(server)

        client, err := rpc.Dial("tcp", serverAddr)
        if err != nil {
            log.Printf("Error connecting to server %s at %s: %v", server, serverAddr, err)
            continue 
        }

        var reply []float64
        err = client.Call("Server.SendPerformance", "", &reply)
        if err != nil {
            log.Printf("Error calling SendPerformance on server %s: %v", server, err)
            client.Close()
            continue
        }

        client.Close() 


        if len(reply) < 2 {
            log.Printf("Invalid reply from server %s: %+v", server, reply)
            continue
        }

        txnExecuted := reply[0]
        latencyMs := reply[1]


        var throughput float64
        if latencyMs > 0 {
            throughput = txnExecuted / (latencyMs / 1000.0) // transactions per second
        } else {
            throughput = 0 
        }

        fmt.Printf("Performance of Client %s:\n", server)
        fmt.Printf("Total Latency (in milliseconds): %.2f ms\n", latencyMs)
        fmt.Printf("Total Transaction: %.0f\n", txnExecuted)
        if latencyMs > 0 {
            fmt.Printf("Throughput: %.2f \n\n", throughput)
        } else {
            fmt.Printf("Throughput: Undefined (latency is zero)\n\n")
        }
    }
}


func generateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privKey, &privKey.PublicKey, nil
}

func signMessage(privateKey *rsa.PrivateKey, message Message) (string, error) {

	messageContent := fmt.Sprintf("%s:%s:%d:%d:%s",
		message.Transaction.Sender,
		message.Transaction.Receiver,
		message.Transaction.Amount,
		message.Timestamp,
		message.ClientName)

	hashed := sha256.Sum256([]byte(messageContent))

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, 0, hashed[:])
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func exportPublicKey(publicKey *rsa.PublicKey) (string, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	return string(pubPEM), nil
}

func sendTransactionToAllReplicas(transaction Transaction, clientName string, privateKey *rsa.PrivateKey, publicKey string) {
	message := Message{
		Transaction: transaction,
		Timestamp:   time.Now().Unix(),
		ClientName:  clientName,
		PublicKey:   publicKey,
	}

	signature, err := signMessage(privateKey, message)
	if err != nil {
		log.Fatalf("Error signing message: %v", err)
	}
	message.Signature = signature

	serverAddresses := []string{
		"localhost:8001",
		"localhost:8002",
		"localhost:8003",
		"localhost:8004",
		"localhost:8005",
		"localhost:8006",
		"localhost:8007",
	}

	for _, serverAddr := range serverAddresses {
		go func(addr string) {
			client, err := rpc.Dial("tcp", addr)
			if err != nil {
				log.Printf("Error connecting to server %s: %v", addr, err)
				return
			}
			defer client.Close()

			var reply string
			err = client.Call("Server.HandleClientRequest", message, &reply)
			if err != nil {
				log.Printf("Error sending transaction to server %s: %v", addr, err)
			} else {
				// log.Printf("Transaction sent to server %s, reply: %s", addr, reply)
			}
		}(serverAddr)
	}
}

func sendNetworkStatus(networkStatus NetworkStatus) {
	allServers := []string{"S1", "S2", "S3", "S4", "S5", "S6", "S7"}

	for _, server := range allServers {
		serverAddr := getServerAddress(strings.TrimSpace(server))
		client, err := rpc.Dial("tcp", serverAddr)
		if err != nil {
			log.Printf("Error connecting to server %s: %v", server, err)
			continue
		}
		defer client.Close()

		var reply string
		err = client.Call("Server.HandleNetworkStatus", networkStatus, &reply)
		if err != nil {
			log.Printf("Error calling remote procedure on server %s: %v", server, err)
		}
	}
}

func processTransactions(csvFile string, clientName string, privateKey *rsa.PrivateKey, publicKey string) {
	file, err := os.Open(csvFile)
	if err != nil {
		log.Fatalf("Failed to open CSV file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		log.Fatalf("Failed to read CSV file: %v", err)
	}

	var currentSet int
	var currentTransactions []Transaction
	var activeServers []string
	var byzantineServers []string

	allServers := []string{"S1", "S2", "S3", "S4", "S5", "S6", "S7"}

	for _, record := range records {
		if len(record) == 0 {
			continue
		}

		if record[2] != "" {
			if currentSet != 0 {
				fmt.Printf("Processing transactions for Set %d:\n", currentSet)

				activeServerMap := make(map[string]bool)
				byzantineServerMap := make(map[string]bool)

				for _, server := range allServers {
					activeServerMap[strings.TrimSpace(server)] = false
					byzantineServerMap[strings.TrimSpace(server)] = false
				}

				for _, server := range activeServers {
					activeServerMap[strings.TrimSpace(server)] = true
				}

				for _, server := range byzantineServers {
					byzantineServerMap[strings.TrimSpace(server)] = true
				}

				networkStatus := NetworkStatus{
					ActiveServers:    activeServerMap,
					ByzantineServers: byzantineServerMap,
				}

				sendNetworkStatus(networkStatus)

				for _, txn := range currentTransactions {
					sendTransactionToAllReplicas(txn, clientName, privateKey, publicKey)
				}

				var response int

				for {
					fmt.Print("1. Continue to the next set? \n")
					fmt.Print("2. Print Log \n")
					fmt.Print("3. Print DB Balance\n")
					fmt.Print("4. Print Status \n")
					fmt.Print("5. Performance Metrics\n")
					fmt.Print("6. Exit\n")
					fmt.Scanln(&response)
					if response == 1 {
						break
					}
					switch response {
					case 1:
						break
					case 2:
						sendCheckLog()
						continue
					case 3:
						sendCheckBalance()
						continue
					case 4:
						sendPrintStatus()
						continue
					case 5:
						sendPerformance()
						continue

					case 6:
						break

					}

				}
				if response == 6 {
					break
				}

			}

			// Reset for the next set
			currentSet, _ = strconv.Atoi(record[0])
			activeServers = parseServers(strings.TrimSpace(record[2]))
			byzantineServers = parseServers(strings.TrimSpace(record[3]))

			currentTransactions = nil
		}

		// Adding transaction for the current set
		if len(record) > 1 {
			transactionStr := record[1]
			transaction := parseTransaction(transactionStr)
			currentTransactions = append(currentTransactions, transaction)
		}
	}

	if currentSet != 0 && len(currentTransactions) > 0 {
		fmt.Printf("Processing transactions for Set %d:\n", currentSet)

		activeServerMap := make(map[string]bool)
		byzantineServerMap := make(map[string]bool)

		for _, server := range allServers {
			activeServerMap[server] = false
			byzantineServerMap[strings.TrimSpace(server)] = false

		}

		for _, server := range activeServers {
			activeServerMap[server] = true
		}

		for _, server := range byzantineServers {
			byzantineServerMap[strings.TrimSpace(server)] = true
		}

		networkStatus := NetworkStatus{
			ActiveServers:    activeServerMap,
			ByzantineServers: byzantineServerMap,
		}

		sendNetworkStatus(networkStatus)

		for _, txn := range currentTransactions {
			sendTransactionToAllReplicas(txn, clientName, privateKey, publicKey)
		}

	}
	var response int
	for {
		fmt.Print("1. Continue to the next set? \n")
		fmt.Print("2. Print Log \n")
		fmt.Print("3. Print DB Balance \n")
		fmt.Print("4. Print Status \n")
		fmt.Print("5. Print Performance\n")
		fmt.Print("6. Exit\n")
		fmt.Scanln(&response)
		if response == 1 {
			break
		}
		switch response {
		case 1:
			break
		case 2:
			sendCheckLog()
			continue
		case 3:
			sendCheckBalance()
			continue
		case 4:
			sendPrintStatus()
			continue
		case 5:
			sendPerformance()
			continue

		case 6:
			break

		}
	}

}

func parseServers(serversStr string) []string {
	serversStr = strings.Trim(serversStr, "[]")
	if serversStr == "" {
		return []string{}
	}
	servers := strings.Split(serversStr, ",")
	for i, server := range servers {
		servers[i] = strings.TrimSpace(server)
	}
	return servers
}

func parseTransaction(transStr string) Transaction {
	transStr = strings.Trim(transStr, "()")
	parts := strings.Split(transStr, ",")
	sender := strings.TrimSpace(strings.TrimSpace(parts[0]))
	receiver := strings.TrimSpace(strings.TrimSpace(parts[1]))
	amount, _ := strconv.Atoi(strings.TrimSpace(parts[2]))
	return Transaction{Sender: sender, Receiver: receiver, Amount: amount}
}

func getServerAddress(sender string) string {
	serverMap := map[string]string{
		"S1": "localhost:8001",
		"S2": "localhost:8002",
		"S3": "localhost:8003",
		"S4": "localhost:8004",
		"S5": "localhost:8005",
		"S6": "localhost:8006",
		"S7": "localhost:8007",
	}
	return serverMap[sender]
}

func main() {
	csvFile := "lab2_Test.csv"
	clientName := "Client"

	privateKey, publicKey, err := generateKeyPair(2048)

	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	publicKeyPEM, err := exportPublicKey(publicKey)

	if err != nil {
		log.Fatalf("Failed to export public key: %v", err)
	}

	processTransactions(csvFile, clientName, privateKey, publicKeyPEM)
}
