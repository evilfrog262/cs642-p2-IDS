#!/usr/bin/env python

import sys, socket
from Queue import *
import dpkt

ARPMap = {
	'\xC0\xA8\x00\x64':'\x7C\xC1\xC3\x94\x93\xB8', #192.168.0.100 
	'\xC0\xA8\x00\x67':'\xD8\x96\x95\x01\xA5\xC9', #192.168.0.103
	'\xC0\xA8\x00\x01':'\xF8\x1A\x67\xCD\x57\x63'  #192.168.0.1
	}

PORT_LIMIT = 100

hostToPortMap = {}
tcpSynMap = {}

class PortScan :
	def __init__(self) :
		self.port = 0;
		self.src = 0;
		self.dst = 0;
		self.num = 0;
	
class TcpSynPkt :
	def __init__(self) :
		self.src = 0;
		self.dst = 0;
		self.num = 0;
		self.ts = 0;

def formatMAC(MACaddr) :
	str = ':'.join(hex.encode('hex') for hex in MACaddr)
	return str

def formatIP(ipaddr) :
	return socket.inet_ntoa(ipaddr)


def checkARPSpoof(arp, pktNum) :
	if (arp.spa in ARPMap) and (arp.sha != ARPMap[arp.spa]):
		print 'Warning: ARP Spoofing attempt from packet number ' + str(pktNum)
		print 'Advertised MAC: ' + formatMAC(arp.sha) 
	return

def checkPortScan(ip, port, pktNum) :
	scan = PortScan()
	scan.src = ip.src
	scan.num = pktNum
	scan.port = port
	scan.dst = ip.dst
	# if this ip is already in the table
	if scan.dst in hostToPortMap.keys() :
		# if it is not a new port ignore it
		for x in hostToPortMap[scan.dst] :
			if x.port == scan.port :
				return
		# if it is a new port add it
		hostToPortMap[scan.dst].append(scan)
	# if this ip is not already in the table
	else :
		print 'Detecting port activity for new IP: ' + formatIP(scan.dst)
		portList = [scan]
		hostToPortMap[scan.dst] = portList
	return

def checkPortScanTCP(ip, tcp, pktNum) :
	checkPortScan(ip, tcp.dport, pktNum)
	return

def checkPortScanUDP(ip, udp, pktNum) :
	checkPortScan(ip, udp.dport, pktNum)
	return

def checkSYNFlood(ip, tcp, pktNum, ts) :
	tcppkt = TcpSynPkt()
	tcppkt.src = ip.src
	tcppkt.dst = ip.dst
	tcppkt.num = pktNum
	tcppkt.ts = ts
	if tcppkt.dst in tcpSynMap.keys() :
		q = tcpSynMap[tcppkt.dst]
		for pkt in q :
			if (tcppkt.ts - pkt.ts) >= 1 :
				q.remove(pkt) #removes item from queue
			else :
				break
		q.append(tcppkt)
	else :
		q = [] 
		q.append(tcppkt)
		tcpSynMap[tcppkt.dst] = q
	if len(tcpSynMap[tcppkt.dst]) > 100 :
		print 'Warning: SYN flood detected'
		print 'Source IP: ' + formatIP(tcppkt.src)
		print 'Dest IP: ' + formatIP(tcppkt.dst)
		pktList = []
		for pkt in tcpSynMap[tcppkt.dst] :
			pktList.append(pkt.num)
		print 'Offending packets'
		print pktList
		tcpSynMap.pop(tcppkt.dst)

	return	


# Beginning of main execution
if len(sys.argv) != 2 :
	print("Usage: python IDS.py <pcap file name>")
	sys.exit(0)

pcapFile = sys.argv[1]
f = open(pcapFile)
pcap = dpkt.pcap.Reader(f)

pktNum = 0

for ts, buf in pcap :
	eth = dpkt.ethernet.Ethernet(buf)
 	ethdata = eth.data
 	if type(ethdata) is dpkt.arp.ARP :
		checkARPSpoof(ethdata, pktNum)
	elif type(ethdata) is dpkt.ip.IP :
		ipdata = ethdata.data

		if type(ipdata) is dpkt.tcp.TCP :
			tcp = ipdata
			if (tcp.flags & dpkt.tcp.TH_SYN) != 0 :
				checkPortScanTCP(ethdata, tcp, pktNum)
				checkSYNFlood(ethdata, tcp, pktNum, ts)
		elif type(ipdata) is dpkt.udp.UDP :
			udp = ipdata
			checkPortScanUDP(ethdata, udp, pktNum)
	pktNum += 1

for ipaddr in hostToPortMap :
	if len(hostToPortMap[ipaddr]) > PORT_LIMIT :
		firstPacket = hostToPortMap[ipaddr][0]
		print formatIP(ipaddr)
		packetList = []
		print 'Warning: Port Scan detected on IP ' + formatIP(firstPacket.dst)
		print 'Scanned by IP ' + formatIP(firstPacket.src)
		print 'Offending Packets: '
		for scan in hostToPortMap[ipaddr] :	
			packetList.append(scan.num)
		print packetList

		
f.close()

