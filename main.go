package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type StunResp struct {
	Resp         bool
	ExternalIP   string
	ExternalPort int
	SourceIP     string
	SourcePort   int
	ChangedIP    string
	ChangedPort  int
	err          error
}

// Types for a STUN message

const (
	BindRequestMsg = "0001"
)

var msgTypes = map[string]string{
	"0001": "BindRequestMsg",
	"0101": "BindResponseMsg",
	"0111": "BindErrorResponseMsg",
	"0002": "SharedSecretRequestMsg",
	"0102": "SharedSecretResponseMsg",
	"0112": "SharedSecretErrorResponseMsg",
}

const (
	MappedAddress   = "0001"
	ResponseAddress = "0002"
	ChangeRequest   = "0003"
	SourceAddress   = "0004"
	ChangedAddress  = "0005"
)

// NAT Types
const (
	BLOCKED                = "Blocked"
	OPEN_INTERNET          = "Open Internet"
	FULL_CONE              = "Full Cone"
	SYMMETRIC_UDP_FIREWALL = "Symmetric UDP Firewall"
	RESTRICTED_NAT         = "Restric NAT"
	RESTRICTED_PORT_NAT    = "Restric Port NAT"
	SYMMETRIC_NAT          = "Symmetric NAT"
	ERROR                  = "Error"
)

// Response Attributes
const (
	EXT_IP       = "ExternalIP"
	EXT_PORT     = "ExternalPort"
	SRC_IP       = "SourceIP"
	SRC_PORT     = "SourcePort"
	CHANGED_IP   = "ChangedIP"
	CHANGED_PORT = "ChangedPort"
	RESP         = "Resp"
)

const (
	CHANGE_ADDR_ERR = "Error occurred during Test on Changed IP and Port"
	LOGS_ACTIVE     = "LOGS-ACTIVE"
	SOCKET_TIMEOUT  = 3
	MAX_RETRIES     = 3
)

var sourceIp string
var sourcePort int

var transactionIds []string
var socket *net.UDPConn

/*
   #######################
   Generic/Re-Used Methods
   #######################
*/

func pad(num byte, size int) string {
	padstr := "%0" + strconv.FormatInt(int64(size), 10) + "d"
	return fmt.Sprintf(padstr, num)
}

func bytesToStr(bytes []byte) string {
	first := fmt.Sprintf("%02x", bytes[0])
	second := ""
	if len(bytes) > 1 {
		second = fmt.Sprintf("%02x", bytes[1])
	}
	return fmt.Sprintf("%s%s", first, second)
}

func bytesValToMsgType(bytes []byte) string {
	code := bytesToStr(bytes)
	return msgTypes[code]
}

func convertToHexBuffer(text string) ([]byte, error) {
	data, err := hex.DecodeString(strings.ToUpper(text))
	if err != nil {
		panic(err)
	}
	return data, err
}

func hexValToInt(hex string) int32 {
	value, _ := strconv.ParseInt(hex, 16, 32)
	return int32(value)
}

func getModeFromArray(array []string) string {
	modeMap := make(map[string]int, 1)
	modeElement := array[0]
	maxCount := 1

	if len(array) == 0 {
		return ""
	}

	for i := 0; i < len(array); i++ {
		elem := array[i]
		modeMap[elem]++
		if modeMap[elem] > maxCount {
			modeElement = elem
			maxCount = modeMap[elem]
		}
	}
	return modeElement
}

/*
   #########################
   Main Methods
   #########################
*/

func getIpInfo(logging bool, stunHost string, stunPort int, index int) (string, error) {
	natType, err := getNatType(logging, sourceIp, stunHost, stunPort)

	if err != nil {
		return "Error", err
	}
	// If a network error occurred then try running the test again
	if natType == CHANGE_ADDR_ERR || natType == BLOCKED {
		return getIpInfo(logging, stunHost, stunPort, index)
	}

	if logging {
		fmt.Printf("Test #%v - NAT TYPE: %s\n", index, natType)
	}
	return natType, nil
}

func genTransactionId() string {
	// Generates a numeric transaction ID
	return fmt.Sprintf("%032d", rand.Uint32())
}

func handleStunTestResponse(address string, port int, message string) StunResp {
	responseVal := StunResp{
		Resp:         false,
		ExternalIP:   "",
		ExternalPort: 0,
		SourceIP:     "",
		SourcePort:   0,
		ChangedIP:    "",
		ChangedPort:  0,
	}

	buf, _ := hex.DecodeString(message)
	msgType := buf[0:2]

	// Check the response message type
	codeMsgType := bytesValToMsgType(msgType)
	bindRespMsg := codeMsgType == "BindResponseMsg"

	// Check that the transaction IDs match, 0xc2 value is removed as it is
	// an annoying UTF-8 encode byte that messes up the entire comparison
	var transIdMatch string

	for i := 0; i < len(transactionIds); i++ {

		dataBuff, _ := hex.DecodeString(message)
		dataBuff = dataBuff[4:30]
		data := fmt.Sprintf("%x", dataBuff)

		if strings.Contains(data, transactionIds[i]) {
			transIdMatch = transactionIds[i]
			break
		}
	}

	if bindRespMsg && transIdMatch != "" {
		//transactionIds[0:len(transactionIds)]
		// This is where the fun begins...
		responseVal.Resp = true
		msgLen := hexValToInt(fmt.Sprintf("%x", buf[2:4]))

		lengthRemaining := msgLen
		base := int32(20)

		for lengthRemaining > 0 {
			attrType := bytesToStr(buf[base : base+2])
			attrLen := hexValToInt(strings.ReplaceAll(bytesToStr(buf[base+2:base+4]), "/^0+/", ""))

			// Fetch port and ipAddr value from buffer
			port := int(hexValToInt(bytesToStr(buf[base+6 : base+8])))
			octA := hexValToInt(bytesToStr(buf[base+8 : base+9]))
			octB := hexValToInt(bytesToStr(buf[base+9 : base+10]))
			octC := hexValToInt(bytesToStr(buf[base+10 : base+11]))
			octD := hexValToInt(bytesToStr(buf[base+11 : base+12]))
			ipAddr := fmt.Sprintf("%v.%v.%v.%v", octA, octB, octC, octD)

			switch attrType {
			case MappedAddress:
				responseVal.ExternalIP = ipAddr
				responseVal.ExternalPort = port
			case SourceAddress:
				responseVal.SourceIP = ipAddr
				responseVal.SourcePort = port
			case ChangedAddress:
				responseVal.ChangedIP = ipAddr
				responseVal.ChangedPort = port

			}

			base = base + 4 + attrLen
			lengthRemaining = lengthRemaining - (4 + attrLen)
		}
	} else {
		fmt.Println("No match")
	}

	return responseVal
}

func sendMessage(logging bool, host string, port int, sendData string, counter int, recursiveSendData string) StunResp {
	stunResp := StunResp{}

	socket.SetReadDeadline(time.Now().Add(SOCKET_TIMEOUT * time.Second))

	var dataToSend string

	if recursiveSendData != "" {
		dataToSend = recursiveSendData
	} else {
		dataToSend = sendData
	}

	strLen := pad(byte(len(dataToSend)/2), 4)
	// Generate a transaction ID and push it to list
	transactionId := genTransactionId()
	transactionIds = append(transactionIds, transactionId)

	// Generate hex buffer composed of msg, length, transaction ID, and data to send
	prxData, err := convertToHexBuffer(fmt.Sprintf("%s%s", BindRequestMsg, strLen))
	if err != nil {
		stunResp.err = err
		return stunResp
	}
	transId, err := convertToHexBuffer(transactionId)
	if err != nil {
		stunResp.err = err
		return stunResp
	}
	sndData, err := convertToHexBuffer(dataToSend)
	if err != nil {
		stunResp.err = err
		return stunResp
	}

	finalData := append(prxData, transId[0:16]...)
	finalData = append(finalData, sndData...)

	addr := net.UDPAddr{
		IP:   net.ParseIP(host),
		Port: port,
	}

	// Sending stun message
	result := StunResp{}
	_, err = socket.WriteToUDP(finalData, &addr)
	if err != nil {
		if logging {
			fmt.Printf("Couldn't send response %v\n", err)
		}
		result.err = err
	} else {
		data := make([]byte, 5048)
		_, remoteAddress, err := socket.ReadFromUDP(data)
		if err != nil {
			if logging {
				fmt.Printf("Socket read error %v\n", err)
			}
			result.err = err
		} else {
			message := string(data[:])
			//Received something from the stun server, parse the response
			stunResp = handleStunTestResponse(remoteAddress.IP.String(), remoteAddress.Port, message)
		}

	}
	if stunResp.err != nil {
		if counter >= MAX_RETRIES {
			return stunResp
		}
		stunResp = sendMessage(logging, host, port, sendData, counter+1, dataToSend)
	}

	return stunResp
}

func stunTest(logging bool, host string, port int, sendData string) StunResp {
	var err error
	stunResp := StunResp{}

	if err != nil {
		if logging {
			fmt.Println(err.Error())
		}
		stunResp.err = err
		return stunResp
	}
	stunResp = sendMessage(logging, host, port, sendData, 0, "")

	return stunResp
}

func getNatType(logging bool, sourceIp string, stunHost string, stunPort int) (string, error) {
	var natType string
	var err error
	var stunResult StunResp
	response := false

	if stunHost != "" {
		stunResult = stunTest(logging, stunHost, stunPort, "")
		if stunResult.err != nil {
			return "", err
		}
		response = stunResult.Resp
	}
	if !response || stunResult.err != nil {
		return BLOCKED, nil
	}

	exIP := stunResult.ExternalIP
	exPort := stunResult.ExternalPort
	changedIP := stunResult.ChangedIP
	changedPort := stunResult.ChangedPort

	msgAttrLen := "0004"

	if stunResult.ExternalIP == sourceIp {
		changeRequest := fmt.Sprintf("%s%s00000006", ChangeRequest, msgAttrLen)
		newStunResult := stunTest(logging, stunHost, stunPort, changeRequest)
		if newStunResult.Resp || newStunResult.err != nil {
			natType = OPEN_INTERNET
		} else {
			natType = SYMMETRIC_UDP_FIREWALL
		}
	} else {
		changeRequest := fmt.Sprintf("%s%s00000006", ChangeRequest, msgAttrLen)
		secondStunResult := stunTest(logging, stunHost, stunPort, changeRequest)
		if secondStunResult.Resp && secondStunResult.err == nil {
			natType = FULL_CONE
		} else {
			secondStunResult := stunTest(logging, changedIP, changedPort, "")
			if !secondStunResult.Resp || secondStunResult.err != nil {
				natType = CHANGE_ADDR_ERR
			} else {
				if exIP == secondStunResult.ExternalIP && exPort == secondStunResult.ExternalPort {
					changePortRequest := fmt.Sprintf("%s%s00000002", ChangeRequest, msgAttrLen)
					thirdStunResult := stunTest(logging, changedIP, stunPort, changePortRequest)

					if thirdStunResult.Resp && thirdStunResult.err == nil {
						natType = RESTRICTED_NAT
					} else {
						natType = RESTRICTED_PORT_NAT
					}
				} else {
					natType = SYMMETRIC_NAT
				}
			}
		}
	}

	return natType, nil
}

/*
   ##########################
   Socket Setup & Main Method
   ##########################
*/

func GetDeterminedNatType(logging bool, sampleCount int, stunHost string) (string, error) {
	//init
	var err error
	sourceIp = "0.0.0.0"
	sourcePort = 54320
	transactionIds = make([]string, 0)

	if stunHost == "" {
		stunHost = "stun.sipgate.net"
	}
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				//opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
			if err != nil {
				if logging {
					fmt.Printf("Cannot create control %v\n", err)
				}
				return err
			}
			return opErr
		},
	}

	lp, err := lc.ListenPacket(context.TODO(), "udp", sourceIp+":"+strconv.FormatInt(int64(sourcePort), 10))
	if err != nil {
		log.Fatalf("dial failed: %v", err)
	}

	socket = lp.(*net.UDPConn)
	destAddress, err := net.LookupIP(stunHost)
	if err != nil {
		return "", err
	}

	resultsList := make([]string, 0)
	// Take n number of samples and find mode value (to determine most probable NAT type)
	for i := 0; i < sampleCount; i++ {
		ipInfo, err := getIpInfo(logging, destAddress[0].String(), 3478, i+1)
		if err == nil {
			resultsList = append(resultsList, ipInfo)
		} else {
			fmt.Println(err)
		}
	}

	socket.Close()
	determinedNatType := getModeFromArray(resultsList)
	if logging {
		fmt.Printf("\nDetermined NAT Type: %v\n", determinedNatType)
		fmt.Printf("A mode value is selected using a %v test samples as failed responses via UDP can cause inaccurate results.\n", sampleCount)
	}
	return determinedNatType, nil
}

func main() {
	GetDeterminedNatType(true, 10, "stun.sipgate.net")
}
