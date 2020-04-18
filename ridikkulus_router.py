#!/usr/bin/env python3
# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
# Copyright 2019 Alex Afanasyev
#
# This program is free software: you can redistribute it and/or modify it under the terms of
# the GNU General Public License as published by the Free Software Foundation, either version
# 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program.
# If not, see <http://www.gnu.org/licenses/>.

from router_base import SimpleRouterBase, PoxConnectorApp, headers

from ridikkulus_routing_table import RoutingTable
from ridikkulus_arp_cache import ArpCache

import sys

class SimpleRouter(SimpleRouterBase):
 
    #
    # IMPLEMENT THIS METHOD TO HANDLE THE RECEIVED PACKETS
    #
    # This method is called each time the router receives a packet on
    # the interface.  The packet buffer \p packet and the receiving
    # interface \p inIface are passed in as parameters. The packet is
    # complete with ethernet headers.
    #
    def handlePacket(self, packet, inIface):
        print ("--------------------------------")
        print("...Got packet of size %d on interface %s" % (len(packet), inIface), file=sys.stderr)
        self.printEthPacket(packet)
        pkt = headers.EtherHeader()
        decodeLength = pkt.decode(packet)        
        print ("Interface:      " + str(inIface))
        #  0x0806 = 2054 - ARP
        #  0x0800 = 2048 - IPV4
        arpT = 2054
        ipvT = 2048
        iface = self.findIfaceByName(inIface)
        
        if not iface:
            print("Received packet, but interface is unknown, ignoring", file=sys.stderr)
            return
        print ("--------------------------------")
        
        print("Iface table:\n--------------------------------")
        
        for ifc in self.ifaces:
            print (ifc.name, ifc.mac, ifc.ip)           
        

        if pkt.type == arpT:
            self.arpProcess(packet, iface)            
        elif pkt.type == ipvT:
            self.ipProcess(pkt)

        
        #
        # FILL IN THE REST
        #
    
    def arpProcess(self, packet, iface):
        ethPkt = headers.EtherHeader()
        pkt = headers.ArpHeader()
        decodeLength = ethPkt.decode(packet)     
        pkt.decode(packet[decodeLength:])        
        print ("--------------------------------")
        print ("...started arp process")
        thisIface = iface      
        replyArpPkt = headers.ArpHeader(hln=6, pln=4, op=2, sha=thisIface.mac, sip=thisIface.ip, tha=pkt.sha, tip=pkt.sip)
        buf = replyArpPkt.encode()
        replyEthPkt = headers.EtherHeader(shost=thisIface.mac, dhost=pkt.sha, type=2054)
        buf = replyEthPkt.encode() + buf
        print ("...sending Arp Reply")
        self.printEthPacket(buf)
        self.sendPacket(packet,thisIface.name)
        #for iface in self.ifaces:
        #    if pkt.tip != iface.ip:
        #        self.sendPacket(packet,iface)
        pass

    def ipProcess(self,packet):
        print ("...started ipv4 process")
        pass
    
    def printArpPacket(self,packet):
        pkt = headers.ArpHeader()
        pkt.decode(packet)
        print("--------------------------------")
        print("Arp Header")
        print("--------------------------------") 
        print ("OP Code:    " + "request" if pkt.op == 1 else "reply")
        print ("Sender HW:  " + str(pkt.sha))
        print ("Sender IP:  " + str(pkt.sip))
        print ("Target HW:  " + str(pkt.tha))
        print ("Target IP:  " + str(pkt.tip))
        pass

    def printEthPacket(self, packet):
        pkt = headers.EtherHeader()        
        decodeLength = pkt.decode(packet) 
        print("--------------------------------")
        print("Ethernet Header")
        print("--------------------------------")    
        print ("Source MAC: " + str(pkt.shost))
        print ("Dest MAC:   " + str(pkt.dhost))
        print ("Type:       " + str(pkt.type))
        arpT = 2054
        ipvT = 2048
        if pkt.type == arpT:
           self.printArpPacket(packet[decodeLength:])
        pass
    #
    # USE THIS METHOD TO SEND PACKETS OUT
    #
    # Call this method to send packet \p packet from the router on interface \p outIface
    #
    def sendPacket(self, packet, outIface):
        super().sendPacket(packet, outIface)

    ##############################################################################
    ######################### DO NOT EDIT THE REST ###############################
    ##############################################################################

    def __init__(self):
        super().__init__(RoutingTable(), ArpCache(self))
    
if __name__ == '__main__':
    rtr = SimpleRouter()
    app = PoxConnectorApp(rtr)
    app.main(sys.argv, "router.config")
