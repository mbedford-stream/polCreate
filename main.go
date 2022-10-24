package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/Juniper/go-netconf/netconf"
	"github.com/fatih/color"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func readJSON(jsonFile string) (NewRuleData, error) {
	var jsonPayload NewRuleData
	if !FileExists(jsonFile) || FileIsADirectory(jsonFile) {
		return jsonPayload, errors.New("check inputs file")
	}
	fileContent, err := ioutil.ReadFile(jsonFile)
	if err != nil {
		log.Fatal("Error when opening file: ", err)
	}
	// var jsonPayload NewRuleData
	err = json.Unmarshal(fileContent, &jsonPayload)
	if err != nil {
		log.Fatal("Error during Unmarshal(): ", err)
	}

	return jsonPayload, nil
}

// FileExists tests to see if a file..... exists
func FileExists(fileName string) bool {
	if _, err := os.Stat(fileName); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// FileIsADirectory - tests a file
func FileIsADirectory(file string) bool {
	if stat, err := os.Stat(file); err == nil && stat.IsDir() {
		// path is a directory
		return true
	}
	return false
}

func getZone(openSession *netconf.Session, lookupIP string) (string, error) {
	lookupIP = strings.Split(lookupIP, "/")[0]
	getRouteRPC := fmt.Sprintf("<get-route-information><destination>%s</destination><active-path/></get-route-information>", lookupIP)

	var routeResp RouteInformation
	getRouteResp, err := getRPC(openSession, getRouteRPC)
	if err != nil {
		return "", err
	}

	err = xml.Unmarshal([]byte(getRouteResp.Data), &routeResp)
	if err != nil {
		return "", err
	}

	if len(routeResp.RouteTable) == 0 {
		return "", errors.New("route not found in tables")
	}

	var outputInt string
	for _, v := range routeResp.RouteTable {
		if v.TableName == "mgmt_junos.inet.0" {
			continue
		}
		outputInt = v.Rt.RtEntry.Nh.Via
		break
	}

	getZoneRPC := fmt.Sprintf("<get-interface-information><interface-name>%s</interface-name></get-interface-information>", outputInt)
	var zoneResp InterfaceInformation
	getZoneResp, err := getRPC(openSession, getZoneRPC)
	if err != nil {
		return "", err
	}

	err = xml.Unmarshal([]byte(getZoneResp.Data), &zoneResp)
	if err != nil {
		return "", err
	}

	return zoneResp.LogicalInterface.LogicalInterfaceZoneName, nil

}

func getRPC(openSession *netconf.Session, rpcCommand string) (*netconf.RPCReply, error) {
	// Sends raw XML
	res, err := openSession.Exec(netconf.RawMethod(rpcCommand))
	if err != nil {
		return nil, err
	}
	return res, nil
}

// func checkIP(testIP string) bool {
// 	ipConv := net.ParseIP(testIP)
// 	return ipConv != nil
// }

func getNetwork(testCIDR string) (net.IP, *net.IPNet, error) {
	if len(strings.Split(testCIDR, "/")) != 2 {
		testCIDR = fmt.Sprintf("%s/32", testCIDR)
	}
	var ipAddr net.IP
	var netAddr *net.IPNet
	ipAddr, netAddr, err := net.ParseCIDR(testCIDR)
	if err != nil {
		return ipAddr, netAddr, err
	}

	return ipAddr, netAddr, err
}

func getCreds(authService string) (string, string) {
	// Reusable function used to get username and password from terminal so I don't have to hard code a service account.
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Enter Username for %s: ", authService)
	username, _ := reader.ReadString('\n')
	fmt.Print("Enter Password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("\nPassword typed: " + string(bytePassword))
	}
	password := string(bytePassword)
	fmt.Println("")
	return strings.TrimSpace(username), strings.TrimSpace(password)
}

// ==================================================
//
// Main function start
//
// ==================================================

func main() {
	firewallList := make(map[string]string)
	firewallList["Lab"] = "172.25.0.190"
	firewallList["Metro"] = "172.25.0.1"
	firewallList["Dallas"] = "172.27.0.1"

	keys := make([]string, 0, len(firewallList))
	for k := range firewallList {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fmt.Println("Secutity Policy Lookup\n=========================")

	i := 1
	firewallMenu := make(map[string]string)
	for _, k := range keys {
		fmt.Printf("%d: %s\n", i, k)
		firewallMenu[strconv.Itoa(i)] = firewallList[k]
		i++

	}

	var reader *bufio.Reader
	var fwChoice string

	for {
		reader = bufio.NewReader(os.Stdin)
		fmt.Print("Choose a firewall to check: ")
		fwChoice, _ = reader.ReadString('\n')
		fwChoice = strings.TrimRight(fwChoice, "\r\n")
		choiceInt, err := strconv.Atoi(fwChoice)
		if err != nil {
			choiceInt = 1000
		}
		if choiceInt <= len(firewallMenu) {
			break
		}
	}

	fmt.Println(firewallMenu[fwChoice])

	var newDataFile string

	for {
		reader = bufio.NewReader(os.Stdin)
		fmt.Print("Location of new rule data file: ")
		newDataFile, _ = reader.ReadString('\n')
		newDataFile = strings.TrimRight(newDataFile, "\r\n")

		if FileExists(newDataFile) {
			break
		}
	}

	newRuleJSON, err := readJSON(newDataFile)
	if err != nil {
		log.Fatal(err)
	}

	if newRuleJSON.RefNumber == "" {
		log.Fatal("Need a ref number, boss")
	}

	if len(newRuleJSON.Destinations) == 0 {
		log.Fatal("No destinations found in rule definition")
	}
	if len(newRuleJSON.Sources) == 0 {
		log.Fatal("No sources found in rule definition")
	}
	if len(newRuleJSON.TcpPorts) == 0 && len(newRuleJSON.UdpPorts) == 0 {
		log.Fatal("No valid ports found in rule definition")
	}
	// Check all provided destination IPs for valid IP
	sourceIPs := make(map[string][]string)
	destinationIPs := make(map[string][]string)
	var tcpPorts []string
	var udpPorts []string

	fmt.Println()

	fwUser, fwPass := getCreds("firewall: ")

	sshConfig := &ssh.ClientConfig{
		User:            fwUser,
		Auth:            []ssh.AuthMethod{ssh.Password(fwPass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	devSession, err := netconf.DialSSH(firewallMenu[fwChoice], sshConfig)
	if err != nil {
		log.Printf("Error connecting to device")
	}
	defer devSession.Close()

	for _, v := range newRuleJSON.Destinations {
		_, netAddr, err := getNetwork(v)
		if err != nil {
			log.Fatalf("%s", color.RedString("%s is not a valid IP in Destinations", v))
		}
		toZone, err := getZone(devSession, netAddr.String())
		if err != nil {
			log.Fatalf("%s", color.RedString("%s %s", "Source", err))
		}
		destinationIPs[strings.Trim(toZone, "\n")] = append(destinationIPs[strings.Trim(toZone, "\n")], strings.Trim(netAddr.String(), "\r\n"))
	}
	// Check all provided Source IPs for valid IP
	for _, v := range newRuleJSON.Sources {
		_, netAddr, err := getNetwork(v)
		if err != nil {
			log.Fatalf("%s", color.RedString("%s is not a valid IP in Destinations", netAddr))
		}
		fromZone, err := getZone(devSession, netAddr.String())
		if err != nil {
			log.Fatalf("%s", color.RedString("%s %s", "Source", err))
		}
		sourceIPs[strings.Trim(fromZone, "\n")] = append(sourceIPs[strings.Trim(fromZone, "\n")], strings.Trim(netAddr.String(), "\r\n"))

	}
	// Check all TCP and UDP ports for valid int
	for _, v := range newRuleJSON.TcpPorts {
		if len(strings.Split(v, "-")) == 2 {
			for _, i := range strings.Split(v, "-") {
				_, err := strconv.Atoi(i)
				if err != nil {
					log.Fatalf("%s", color.RedString("%s is not a valid TCP port", i))
				}

			}
		} else {
			_, err := strconv.Atoi(v)
			if err != nil {
				log.Fatalf("%s", color.RedString("%s is not a valid TCP port", v))
			}
		}
		tcpPorts = append(tcpPorts, v)
	}

	for _, v := range newRuleJSON.UdpPorts {
		if len(strings.Split(v, "-")) == 2 {
			for _, i := range strings.Split(v, "-") {
				_, err := strconv.Atoi(i)
				if err != nil {
					log.Fatalf("%s", color.RedString("%s is not a valid UDP port", i))
				}

			}
		} else {
			_, err := strconv.Atoi(v)
			if err != nil {
				log.Fatalf("%s", color.RedString("%s is not a valid UDP port", v))
			}
		}
		udpPorts = append(udpPorts, v)
	}

	sourcesList := make(map[string]string)
	destinationsList := make(map[string]string)
	var appList []string
	color.Green("Source IP information for new policy\n")
	for k, v := range sourceIPs {
		for _, v2 := range v {
			ipUnderscore := strings.Replace(strings.Replace(v2, ".", "_", -1), "/", "_", -1)
			sourceIPAddrBook := fmt.Sprintf("set groups automated security address-book global address %s %s", fmt.Sprintf("addr-%s-%s", k, ipUnderscore), v2)
			fmt.Printf("%s\n", sourceIPAddrBook)
			sourceIPAddrSet := fmt.Sprintf("set groups automated security address-book global address-set %s address %s", fmt.Sprintf("%s-%s-SRC-Set", newRuleJSON.RefNumber, k), fmt.Sprintf("addr-%s-%s", k, ipUnderscore))
			sourcesList[k] = fmt.Sprintf("%s-%s-SRC-Set", newRuleJSON.RefNumber, k)
			fmt.Printf("%s\n", sourceIPAddrSet)
		}
	}
	fmt.Println("=========================")
	color.Green("Destination IP information for new policy\n")
	for k, v := range destinationIPs {
		for _, v2 := range v {
			ipUnderscore := strings.Replace(strings.Replace(v2, ".", "_", -1), "/", "_", -1)
			destIPAddrBook := fmt.Sprintf("set groups automated security address-book global address %s %s", fmt.Sprintf("addr-%s-%s", k, ipUnderscore), v2)
			fmt.Printf("%s\n", destIPAddrBook)
			destIPAddrSet := fmt.Sprintf("set groups automated security address-book global address-set %s address %s", fmt.Sprintf("%s-%s-DST-Set", newRuleJSON.RefNumber, k), fmt.Sprintf("addr-%s-%s", k, ipUnderscore))
			destinationsList[k] = fmt.Sprintf("%s-%s-DST-Set", newRuleJSON.RefNumber, k)
			fmt.Printf("%s\n", destIPAddrSet)
		}
	}

	fmt.Println("=========================")
	color.Green("TCP Ports")
	for _, v := range tcpPorts {
		tcpAppProt := fmt.Sprintf("set groups automated applications application %s-%s protocol tcp", "TCP", v)
		tcpAppPort := fmt.Sprintf("set groups automated applications application %s-%s destination-port %s", "TCP", v, v)
		fmt.Printf("%s\n%s\n", tcpAppProt, tcpAppPort)
		tcpAppSet := fmt.Sprintf("set groups automated applications application-set %s-tcp-app-set application %s-%s", newRuleJSON.RefNumber, "TCP", v)
		fmt.Printf("%s\n", tcpAppSet)
		appList = append(appList, fmt.Sprintf("%s-tcp-app-set", newRuleJSON.RefNumber))
	}
	fmt.Println("=========================")
	color.Green("UDP Ports")
	for _, v := range udpPorts {
		udpAppProt := fmt.Sprintf("set groups automated applications application %s-%s protocol udp", "UDP", v)
		udpAppPort := fmt.Sprintf("set groups automated applications application %s-%s destination-port %s", "UDP", v, v)
		fmt.Printf("%s\n%s\n", udpAppProt, udpAppPort)
		udpAppSet := fmt.Sprintf("set groups automated applications application-set %s-udp-app-set application %s-%s", newRuleJSON.RefNumber, "UDP", v)
		fmt.Printf("%s\n", udpAppSet)
		appList = append(appList, fmt.Sprintf("%s-udp-app-set", newRuleJSON.RefNumber))
	}
	fmt.Println("=========================")
	color.Green("Policy Create")
	for kS, vS := range sourcesList {
		for kD, vD := range destinationsList {
			fmt.Printf("set groups automated security policies from-zone %s to-zone %s policy %s match source-address %s\n", kS, kD, fmt.Sprintf("%s-Policy", newRuleJSON.RefNumber), vS)
			fmt.Printf("set groups automated security policies from-zone %s to-zone %s policy %s match destination-address %s\n", kS, kD, fmt.Sprintf("%s-Policy", newRuleJSON.RefNumber), vD)
			for _, vA := range appList {
				fmt.Printf("set groups automated security policies from-zone %s to-zone %s policy %s match application %s\n", kS, kD, fmt.Sprintf("%s-Policy", newRuleJSON.RefNumber), vA)
			}
			fmt.Printf("set groups automated security policies from-zone %s to-zone %s policy %s then permit\n", kS, kD, fmt.Sprintf("%s-Policy", newRuleJSON.RefNumber))
			fmt.Printf("set groups automated security policies from-zone %s to-zone %s policy %s then log session-init session-close\n", kS, kD, fmt.Sprintf("%s-Policy", newRuleJSON.RefNumber))

		}

	}

}
