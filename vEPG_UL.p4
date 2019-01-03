/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<32> digest_t;

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<16> ETHERTYPE_VLAN = 0x8100;

const bit<8>  IPPROTO_ICMP   = 0x01;
const bit<8>  IPPROTO_IPv4   = 0x04;
const bit<8>  IPPROTO_TCP   = 0x06;
const bit<8>  IPPROTO_UDP   = 0x11;

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

const bit<8> ICMP_ECHO_REQUEST = 8;
const bit<8> ICMP_ECHO_REPLY   = 0;

const bit<16> GTP_UDP_PORT     = 2152;

const bit<16>  UDP_PORT_VXLAN   = 4789;

const digest_t MAC_LEARN_RECEIVER = 1;
const digest_t ARP_LEARN_RECEIVER = 1025;

const bit<48> OWN_MAC = 0x001122334455;
const bit<48> BCAST_MAC = 0xFFFFFFFFFFFF;
const bit<32> GW_IP = 0x0A000001; // 10.0.0.1

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<9> port_id_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}



header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}



header vxlan_t  {
	bit<8> flags;
	bit<24> reserved1;
	bit<24> vni;
	bit<8> reserved2;
	
}


header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
}

/* GPRS Tunnelling Protocol (GTP) common part for v1 and v2 */

header gtp_t {
	bit<3> version; /* this should be 1 for GTPv1 and 2 for GTPv2 */
	bit<1> pFlag;   /* protocolType for GTPv1 and pFlag for GTPv2 */
	bit<1> tFlag;   /* only used by GTPv2 - teid flag */
	bit<1> eFlag;   /* only used by GTPv1 - E flag */
	bit<1> sFlag;   /* only used by GTPv1 - S flag */
	bit<1> pnFlag;  /* only used by GTPv1 - PN flag */
	bit<8> messageType;
	bit<16> messageLength;
	bit<32> teid;
	
}



/* UDP */

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> plength;
    bit<16> checksum;
}

/* Local metadata */

struct gtp_metadata_t {
	bit<32> teid;
	bit<8> color;
}


struct routing_metadata_t {
    bit<8> nhgrp;
}


struct metadata {
    gtp_metadata_t gtp_metadata;
    routing_metadata_t routing_metadata;
}

struct headers {

    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    udp_t        udp1;

    vxlan_t      vxlan;
    vxlan_t      vxlan1;
    ethernet_t   inner_ethernet;
    ethernet_t   inner1_ethernet;
    ipv4_t       inner1_ipv4;
    ipv4_t       inner11_ipv4;
    ipv4_t       ipv4_1;
    udp_t        inner1_udp;
    udp_t        inner2_udp;
    gtp_t 		 gtp;
    ipv4_t       inner2_ipv4;
    icmp_t       icmp;
    icmp_t       icmp1;

  //icmp_t	     inner_icmp;
    
    
    

}

/************************************************************************
************************ D I G E S T  ***********************************
*************************************************************************/

struct mac_learn_digest {
    bit<48> srcAddr;
    bit<8>  ingress_port;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }


    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPPROTO_UDP  : parse_udp;
            default      : accept;
        }
    }


    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            UDP_PORT_VXLAN : parse_vxlan;
            default      : accept;    
        }
    }


    state parse_vxlan {
        packet.extract(hdr.vxlan);
        transition parse_inner_ethernet;
    }

    state parse_inner_ethernet {
        packet.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.etherType) {
            ETHERTYPE_IPV4: parse_inner1_ipv4;
            default: accept;
        }
    }


    state parse_inner1_ipv4 {
        packet.extract(hdr.inner1_ipv4);
        transition select(hdr.inner1_ipv4.protocol) {
            IPPROTO_UDP  : parse_inner1_udp;
            default      : accept;
        }
    }


    state parse_inner1_udp {
        packet.extract(hdr.inner1_udp);
        transition select(hdr.inner1_udp.dstPort) {
            GTP_UDP_PORT : parse_gtp;
            default      : accept;    
        }
    }


    state parse_gtp {
        packet.extract(hdr.gtp);
        transition select(hdr.gtp.messageType) {
        0xFF   : parse_inner2_ipv4;
        default    : accept;

        }
       // transition parse_inner2_ipv4;
	    
    }


    state parse_inner2_ipv4 {
        packet.extract(hdr.inner2_ipv4);
        transition select(hdr.inner2_ipv4.protocol) {
            IPPROTO_UDP : parse_inner2_udp;
            default      : accept;
        }

    }

    state parse_inner2_udp {
        packet.extract(hdr.inner2_udp);
        transition accept; 
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop();
    }
    
    action mac_learn() {
        digest(MAC_LEARN_RECEIVER, { hdr.ethernet.srcAddr, standard_metadata.ingress_port } );
    }


    action forward(port_id_t port) {
        standard_metadata.egress_spec = port;
	    hdr.ethernet.srcAddr = OWN_MAC;
    }

    action bcast() {
        standard_metadata.egress_spec = 100;
    }

  /* action gtp_encapsulate(bit<32> teid, bit<32> ip) {
        hdr.inner_ipv4.setValid();
        hdr.inner_ipv4 = hdr.ipv4;
	    hdr.inner_udp = hdr.udp;
        hdr.udp.setValid();
        hdr.gtp.setValid();
        hdr.udp.srcPort = GTP_UDP_PORT;
        hdr.udp.dstPort = GTP_UDP_PORT;
        hdr.udp.checksum = 0;
        hdr.udp.plength = hdr.ipv4.totalLen + 8;
        hdr.gtp.version = 1;
        hdr.gtp.pFlag = 1;
        hdr.gtp.messageType = 255;
        hdr.gtp.messageLength = hdr.ipv4.totalLen + 8;
        hdr.ipv4.srcAddr = GW_IP;
        hdr.ipv4.dstAddr = ip;
        hdr.ipv4.protocol = IPPROTO_UDP;
        hdr.ipv4.ttl = 255;
        hdr.ipv4.totalLen = hdr.udp.plength + 28;
        meta.gtp_metadata.teid = teid;
	    hdr.inner_icmp = hdr.icmp;
	    hdr.icmp.setInvalid();
    }

    */


    

    action gtp_decapsulate(ip4Addr_t ip) {

        hdr.ipv4.srcAddr = GW_IP;
        hdr.ipv4.dstAddr = ip;
        
        //hdr.ipv4.dstAddr = ip
        hdr.inner_ethernet.srcAddr = hdr.inner_ethernet.dstAddr;

        hdr.inner1_ipv4.srcAddr = hdr.inner2_ipv4.srcAddr;
        hdr.inner1_ipv4.dstAddr = hdr.inner2_ipv4.dstAddr;


        //hdr.icmp1 = hdr.icmp; 
        hdr.gtp.setInvalid();
        
        hdr.inner1_udp.dstPort =1853;
        hdr.inner1_udp.srcPort =57807;

        

        }

    action set_nhgrp(bit<8> nhgrp) {
        meta.routing_metadata.nhgrp = nhgrp;
	    hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    action pkt_send(mac_addr_t nhmac, port_id_t port , mac_addr_t mac) {
        hdr.ethernet.srcAddr = OWN_MAC; // simplified
        hdr.ethernet.dstAddr = nhmac;
        hdr.inner_ethernet.dstAddr = mac;
      
        standard_metadata.egress_spec = port;
    }

table smac {
    key = {
		standard_metadata.ingress_port : exact;
        hdr.ethernet.srcAddr : exact;
    }
    actions = {mac_learn;}
    size = 512;
    default_action = mac_learn;
}

table dmac {
    key = {
        hdr.ethernet.dstAddr : exact;
    }
    actions = {forward; bcast;}
    size = 512;
    default_action = bcast;
}


table ue_selector {
	key = {
		hdr.ipv4.dstAddr : lpm;
		hdr.udp.dstPort  : exact; /* in most of the cases the mask is 0 */
	}
	actions = { gtp_decapsulate; drop;}
	size = 10000;
    default_action = drop;
}




table ipv4_lpm {
	key = {
		hdr.ipv4.dstAddr : lpm;
	}
	actions = { set_nhgrp; drop; }
	size = 256;
	default_action = drop;
}

table ipv4_forward {
    key = {
		meta.routing_metadata.nhgrp : exact;        
    }
    actions = {pkt_send; drop; }
    size = 64;
    default_action = drop;
}



apply {
	smac.apply();
	dmac.apply();  
   

    if ( (hdr.ethernet.srcAddr == OWN_MAC) || (hdr.ethernet.dstAddr == BCAST_MAC) )

    {  if ( hdr.ipv4.isValid() ) {
	    ue_selector.apply();  
	    ipv4_lpm.apply();
		ipv4_forward.apply();

         }
     }
	    
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control Ipv4ComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
/*	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);*/
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply { 
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.vxlan);
        packet.emit(hdr.inner_ethernet);
        packet.emit(hdr.inner1_ipv4);
        packet.emit(hdr.inner1_udp);
       // packet.emit(hdr.gtp);
       // packet.emit(hdr.inner2_ipv4);
       // packet.emit(hdr.icmp1);
        //packet.emit(hdr.inner2_ipv4);
		 
    	
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
Ipv4ComputeChecksum(),
MyDeparser()
) main;

