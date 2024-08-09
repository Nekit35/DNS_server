package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type Header struct {
	ID      uint16
	QR      uint16
	Opcode  uint16
	AA      uint16
	TC      uint16
	RD      uint16
	RA      uint16
	Z       uint16
	RCODE   uint16
	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
}

type Request struct {
	QNAME  string
	QTYPE  uint8
	QCLASS uint8
}

type DNSRequest struct {
	Header
	Request
}

type Response struct {
	NAME     string
	TYPE     uint16
	CLASS    uint16
	TTL      uint32
	RDLENGTH uint16
	RDATA    [4]uint8
}

type DNSResponse struct {
	Header
	Request
	Response
}

func server(nameToIP map[string][4]uint8) {
	serverAddress, err := net.ResolveUDPAddr("udp", "127.0.0.1:8080")
	if err != nil {
		fmt.Println(err)
		return
	}
	connection, err := net.ListenUDP("udp", serverAddress)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer connection.Close()

	for {
		inputBytes := make([]byte, 512)
		_, clientAddress, err := connection.ReadFromUDP(inputBytes)
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Printf("[%s] Received message from %s: ", time.Now().Format("2006-01-02 15:04:05"), clientAddress)
		fmt.Println(string(inputBytes))
		request, _ := DNSRequestFromHex(string(inputBytes))
		response := DNSResponseConst(request, nameToIP)
		// отправляем сообщение клиенту
		_, err = connection.WriteToUDP([]byte(response.DNSResponseToHex()), clientAddress)
		if err != nil {
			fmt.Println(err)
			continue
		}
	}
}

func client(message string) {
	serverAddress, err := net.ResolveUDPAddr("udp", "127.0.0.1:8080")
	if err != nil {
		fmt.Println(err)
		return
	}
	connection, err := net.DialUDP("udp", nil, serverAddress)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer connection.Close()

	_, err = connection.Write([]byte(message))
	if err != nil {
		fmt.Println(err)

	}

	inputBytes := make([]byte, 1024)
	_, err = connection.Read(inputBytes)
	if err != nil {
		fmt.Println(err)

	}
	fmt.Println(string(inputBytes))
	time.Sleep(3 * time.Second)

}

func (d *DNSRequest) DNSrequestToHex() string {
	var res []string
	res = append(res, fmt.Sprintf("%x", d.ID))
	var flags uint16
	flags |= d.QR << 15
	flags |= d.Opcode << 11
	flags |= d.AA << 10
	flags |= d.TC << 9
	flags |= d.RD << 8
	flags |= d.RA << 7
	flags |= d.Z << 4
	flags |= d.RCODE
	res = append(res, fmt.Sprintf("%04x", flags))
	res = append(res, fmt.Sprintf("%04x", d.QDCOUNT))
	res = append(res, fmt.Sprintf("%04x", d.ANCOUNT))
	res = append(res, fmt.Sprintf("%04x", d.NSCOUNT))
	res = append(res, fmt.Sprintf("%04x", d.ARCOUNT))

	labels := strings.Split(d.QNAME, ".")

	for _, label := range labels {
		src := hex.EncodeToString([]byte(label))
		res = append(res, fmt.Sprintf("%02x", len(src)/2))
		res = append(res, src)

	}
	res = append(res, "00")
	res = append(res, fmt.Sprintf("%04x", d.QTYPE))
	res = append(res, fmt.Sprintf("%04x", d.QCLASS))
	return strings.Join(res, "")
}

func DNSRequestFromHex(hexStr string) (*DNSRequest, error) {
	// Helper function to convert hex string to uint16
	hexToUint16 := func(hexStr string) (uint16, error) {
		val, err := strconv.ParseUint(hexStr, 16, 16)
		return uint16(val), err
	}

	d := &DNSRequest{}
	offset := 0

	// Parse ID
	id, err := hexToUint16(hexStr[offset : offset+4])
	if err != nil {
		return nil, err
	}
	d.ID = id
	offset += 4

	// Parse flags
	flags, err := hexToUint16(hexStr[offset : offset+4])
	if err != nil {
		return nil, err
	}
	d.QR = (flags >> 15) & 0x1
	d.Opcode = (flags >> 11) & 0xF
	d.AA = (flags >> 10) & 0x1
	d.TC = (flags >> 9) & 0x1
	d.RD = (flags >> 8) & 0x1
	d.RA = (flags >> 7) & 0x1
	d.Z = (flags >> 4) & 0x7
	d.RCODE = flags & 0xF
	offset += 4

	// Parse QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
	qdcount, err := hexToUint16(hexStr[offset : offset+4])
	if err != nil {
		return nil, err
	}
	d.QDCOUNT = qdcount
	offset += 4

	ancount, err := hexToUint16(hexStr[offset : offset+4])
	if err != nil {
		return nil, err
	}
	d.ANCOUNT = ancount
	offset += 4

	nscount, err := hexToUint16(hexStr[offset : offset+4])
	if err != nil {
		return nil, err
	}
	d.NSCOUNT = nscount
	offset += 4

	arcount, err := hexToUint16(hexStr[offset : offset+4])
	if err != nil {
		return nil, err
	}
	d.ARCOUNT = arcount
	offset += 4

	// Parse QNAME
	var qnameParts []string
	for {
		labelLen, err := hexToUint16(hexStr[offset : offset+2])
		if err != nil {
			return nil, err
		}
		offset += 2
		if labelLen == 0 {
			break
		}
		label, err := hex.DecodeString(hexStr[offset : offset+int(labelLen*2)])
		if err != nil {
			return nil, err
		}
		offset += int(labelLen * 2)
		qnameParts = append(qnameParts, string(label))
	}
	d.QNAME = strings.Join(qnameParts, ".")

	// Parse QTYPE
	qtype, err := hexToUint16(hexStr[offset : offset+4])
	if err != nil {
		return nil, err
	}
	d.QTYPE = uint8(qtype)
	offset += 4

	// Parse QCLASS
	qclass, err := hexToUint16(hexStr[offset : offset+4])
	if err != nil {
		return nil, err
	}
	d.QCLASS = uint8(qclass)

	return d, nil
}
func DNSResponseConst(req *DNSRequest, nameToIP map[string][4]uint8) DNSResponse {

	header := req.Header
	header.QR = 1
	header.ANCOUNT = 1

	response := Response{
		NAME:     req.Request.QNAME,
		TYPE:     1, // A record
		CLASS:    uint16(req.Request.QCLASS),
		TTL:      1,
		RDLENGTH: 4,
		RDATA:    nameToIP[req.QNAME],
	}
	Res := DNSResponse{
		Header:   header,
		Request:  req.Request,
		Response: response,
	}

	return Res
}

func (d *DNSResponse) DNSResponseToHex() string {
	var res []string
	res = append(res, fmt.Sprintf("%04x", d.ID))

	var flags uint16
	flags |= d.QR << 15
	flags |= d.Opcode << 11
	flags |= d.AA << 10
	flags |= d.TC << 9
	flags |= d.RD << 8
	flags |= d.RA << 7
	flags |= d.Z << 4
	flags |= d.RCODE
	res = append(res, fmt.Sprintf("%04x", flags))

	res = append(res, fmt.Sprintf("%04x", d.QDCOUNT))
	res = append(res, fmt.Sprintf("%04x", d.ANCOUNT))
	res = append(res, fmt.Sprintf("%04x", d.NSCOUNT))
	res = append(res, fmt.Sprintf("%04x", d.ARCOUNT))

	labels := strings.Split(d.Request.QNAME, ".")
	for _, label := range labels {
		src := hex.EncodeToString([]byte(label))
		res = append(res, fmt.Sprintf("%02x", len(label)))
		res = append(res, src)
	}
	res = append(res, "00")

	res = append(res, fmt.Sprintf("%04x", d.Request.QTYPE))
	res = append(res, fmt.Sprintf("%04x", d.Request.QCLASS))

	labels = strings.Split(d.Response.NAME, ".")
	for _, label := range labels {
		src := hex.EncodeToString([]byte(label))
		res = append(res, fmt.Sprintf("%02x", len(label)))
		res = append(res, src)
	}
	res = append(res, "00")

	res = append(res, fmt.Sprintf("%04x", d.Response.TYPE))
	res = append(res, fmt.Sprintf("%04x", d.Response.CLASS))
	res = append(res, fmt.Sprintf("%08x", d.Response.TTL))
	res = append(res, fmt.Sprintf("%04x", d.Response.RDLENGTH))

	rdataHex := fmt.Sprintf("%02x%02x%02x%02x", d.Response.RDATA[0], d.Response.RDATA[1], d.Response.RDATA[2], d.Response.RDATA[3])
	res = append(res, rdataHex)
	return strings.Join(res, "")
}

func parseHexUint16(hexStr string) uint16 {
	value, _ := strconv.ParseUint(hexStr, 16, 16)
	return uint16(value)
}

func parseHexUint32(hexStr string) uint32 {
	value, _ := strconv.ParseUint(hexStr, 16, 32)
	return uint32(value)
}

func DNSResponseFromHex(hexStr string) DNSResponse {
	var resp DNSResponse

	resp.ID = parseHexUint16(hexStr[0:4])

	flags := parseHexUint16(hexStr[4:8])
	resp.QR = (flags >> 15) & 0x1
	resp.Opcode = (flags >> 11) & 0xF
	resp.AA = (flags >> 10) & 0x1
	resp.TC = (flags >> 9) & 0x1
	resp.RD = (flags >> 8) & 0x1
	resp.RA = (flags >> 7) & 0x1
	resp.Z = (flags >> 4) & 0x7
	resp.RCODE = flags & 0xF

	resp.QDCOUNT = parseHexUint16(hexStr[8:12])
	resp.ANCOUNT = parseHexUint16(hexStr[12:16])
	resp.NSCOUNT = parseHexUint16(hexStr[16:20])
	resp.ARCOUNT = parseHexUint16(hexStr[20:24])

	offset := 24
	var qnameLabels []string
	for {
		labelLen, _ := strconv.ParseUint(hexStr[offset:offset+2], 16, 8)
		if labelLen == 0 {
			offset += 2
			break
		}
		offset += 2
		labelHex := hexStr[offset : offset+int(labelLen)*2]
		labelBytes, _ := hex.DecodeString(labelHex)
		qnameLabels = append(qnameLabels, string(labelBytes))
		offset += int(labelLen) * 2
	}
	resp.Request.QNAME = strings.Join(qnameLabels, ".")

	resp.Request.QTYPE = uint8(parseHexUint16(hexStr[offset : offset+4]))
	offset += 4
	resp.Request.QCLASS = uint8(parseHexUint16(hexStr[offset : offset+4]))
	offset += 4

	var nameLabels []string
	for {
		labelLen, _ := strconv.ParseUint(hexStr[offset:offset+2], 16, 8)
		if labelLen == 0 {
			offset += 2
			break
		}
		offset += 2
		labelHex := hexStr[offset : offset+int(labelLen)*2]
		labelBytes, _ := hex.DecodeString(labelHex)
		nameLabels = append(nameLabels, string(labelBytes))
		offset += int(labelLen) * 2
	}
	resp.Response.NAME = strings.Join(nameLabels, ".")

	resp.Response.TYPE = parseHexUint16(hexStr[offset : offset+4])
	offset += 4
	resp.Response.CLASS = parseHexUint16(hexStr[offset : offset+4])
	offset += 4
	resp.Response.TTL = parseHexUint32(hexStr[offset : offset+8])
	offset += 8
	resp.Response.RDLENGTH = parseHexUint16(hexStr[offset : offset+4])
	offset += 4

	rdataHex := hexStr[offset:]
	rdataBytes, _ := hex.DecodeString(rdataHex)
	for i := 0; i < len(rdataBytes) && i < 4; i++ {
		resp.Response.RDATA[i] = rdataBytes[i]
	}

	return resp
}

func main() {
	/* for client
	clientHeader := Header{
		ID:      39886,
		QR:      0,
		Opcode:  0,
		AA:      0,
		TC:      0,
		RD:      1,
		RA:      0,
		Z:       0,
		RCODE:   0,
		QDCOUNT: 1,
		ANCOUNT: 0,
		NSCOUNT: 0,
		ARCOUNT: 0}

	clientRequest := Request{
		QNAME:  "habrahabr.ru",
		QTYPE:  1,
		QCLASS: 1}

	clientDNSRequest := DNSRequest{
		Header:  clientHeader,
		Request: clientRequest,
	}

	fmt.Scanf("%s", &clientDNSRequest.QNAME)
	client(clientDNSRequest.DNSrequestToHex())
	*/
	/* for server
	var nameToIP = map[string][4]uint8{
		"habr.com": {127, 0, 0, 1},
	}

	server(nameToIP)
	*/
}
