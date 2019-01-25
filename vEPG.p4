/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


/*************************************************************************
*********************** C O N S T A N T S ***********************************
*************************************************************************/


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


const bit<48> VIRTUAL_EPG_MAC = 0x001122334488;
const bit<32> VIRTUAL_EPG_IP =  0x0A000302;
const bit<32> VIRTUAL_DCGW_IP = 0x0A000303;
const bit<48> VIRTUAL_DCGW_MAC= 0x001122334489;

typedef bit<2> meter_color_t;
const meter_color_t METER_COLOR_GREEN = 0; 
const meter_color_t METER_COLOR_YELLOW = 1; 
const meter_color_t METER_COLOR_RED = 2;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<9>  port_id_t;

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

header gtp_common_t {
	bit<3> version; /* this should be 1 for GTPv1 and 2 for GTPv2 */
	bit<1> pFlag;   /* protocolType for GTPv1 and pFlag for GTPv2 */
	bit<1> tFlag;   /* only used by GTPv2 - teid flag */
	bit<1> eFlag;   /* only used by GTPv1 - E flag */
	bit<1> sFlag;   /* only used by GTPv1 - S flag */
	bit<1> pnFlag;  /* only used by GTPv1 - PN flag */
	bit<8> messageType;
	bit<16> messageLength;
	
}

header gtp_teid_t {
	bit<32> teid;
}

/* GPRS Tunnelling Protocol (GTP) v1 */

/* 
This header part exists if any of the E, S, or PN flags are on.
*/

header gtpv1_optional_t {
	bit<16> sNumber;
	bit<8> pnNumber;
	bit<8> nextExtHdrType;
}

/* Extension header if E flag is on. */

header gtpv1_extension_hdr_t {
	bit<8> plength; /* length in 4-octet units */
	varbit<128> contents; 
	bit<8> nextExtHdrType;
}

/* GPRS Tunnelling Protocol (GTP) v2 (also known as evolved-GTP or eGTP) */


header gtpv2_ending_t {
	bit<24> sNumber;
	bit<8> reserved;
}

/* TCP */

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
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
	bit<2> color;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
}

header arp_ipv4_t {
    mac_addr_t  sha;
    ipv4_addr_t spa;
    mac_addr_t  tha;
    ipv4_addr_t tpa;
}

struct arp_metadata_t {
    ipv4_addr_t dst_ipv4;
    mac_addr_t  mac_da;
    mac_addr_t  mac_sa;
    port_id_t   egress_port;
    mac_addr_t  my_mac;
}


struct meta_udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> plength;
    bit<16> checksum;
}

struct meta_tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct meta_ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

struct meta_ipv4_t {            
     bit<4>       version;  
     bit<4>       ihl;      
     bit<8>       diffserv; 
     bit<16>      totalLen; 
     bit<16>      identification;
     bit<3>       flags;    
     bit<13>      fragOffset;
     bit<8>       ttl;
     bit<8>       protocol;
     bit<16>      hdrChecksum;
     bit<32>      srcAddr;
     bit<32>      dstAddr;
 }

struct routing_metadata_t {
    bit<8> nhgrp;
    bit<48> mac_da;
}


struct metadata {
    gtp_metadata_t gtp_metadata;
    arp_metadata_t arp_metadata;
    routing_metadata_t routing_metadata;
    meta_ethernet_t meta_ethernet;
    meta_ipv4_t meta_ipv4;
    meta_udp_t meta_udp;
    meta_ethernet_t meta_inner_ethernet;
    meta_ipv4_t meta_inner_ipv4;
    meta_tcp_t meta_inner_tcp;
}


struct headers {
    ethernet_t   ethernet;
    ethernet_t   inner_ethernet;
    ipv4_t       ipv4;
    ipv4_t       inner_ipv4;
    ipv4_t       inner1_ipv4;
    icmp_t       icmp;
    icmp_t       inner_icmp;
    udp_t        udp;
    udp_t        inner_udp;
    udp_t        inner1_udp;
    tcp_t        tcp;
    tcp_t        inner_tcp;
    tcp_t        inner1_tcp;
    vxlan_t      vxlan;
    vxlan_t      vxlan1; 
    arp_t        arp;
    arp_ipv4_t   arp_ipv4;
    gtp_common_t gtp;
    gtp_teid_t   gtp_teid;
    gtpv1_extension_hdr_t gtpv1_extension_hdr;
    gtpv1_optional_t gtpv1_optional;
    gtpv2_ending_t gtpv2_ending;

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
            ETHERTYPE_ARP: parse_arp;
            default: accept;
        }
    }


    state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.htype, hdr.arp.ptype, hdr.arp.hlen,  hdr.arp.plen) {
            (ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4,
            ARP_HLEN_ETHERNET,  ARP_PLEN_IPV4) : parse_arp_ipv4;
            default : accept;
        }
    }


    state parse_arp_ipv4 {
        packet.extract(hdr.arp_ipv4);
        meta.arp_metadata.dst_ipv4 = hdr.arp_ipv4.tpa;
        transition accept;
    }


    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPPROTO_UDP  : parse_udp;
            IPPROTO_ICMP : parse_icmp;
            default      : accept;
        }
    }

     
     state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            UDP_PORT_VXLAN : parse_vxlan;
            default        : accept;    
        }
    }


    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }


    state parse_vxlan {
        packet.extract(hdr.vxlan);
        transition parse_inner_ethernet;
    }

    state parse_inner_ethernet {
        packet.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.etherType) {
            ETHERTYPE_IPV4: parse_inner_ipv4;
            default: accept;
        }
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            IPPROTO_UDP  : parse_inner_udp;
            IPPROTO_TCP  : parse_inner_tcp;
            default      : accept;
        }
    }


    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        transition select(hdr.inner_udp.dstPort) {
            GTP_UDP_PORT : parse_gtp;
            default      : accept;    
        }
    }


    state parse_inner_tcp {
        packet.extract(hdr.inner_tcp);
        transition accept;
    }


    state parse_gtp {
        packet.extract(hdr.gtp);
        transition select(hdr.gtp.version, hdr.gtp.tFlag) { 
           (1,0) : parse_teid;
		   (1,1) : parse_teid;
		   (2,1) : parse_teid;
		   (2,0) : parse_gtpv2;
		   default 	: parse_inner1_ipv4;

		   // default : accept;
	    }
	    
    }

    state parse_teid {
        packet.extract(hdr.gtp_teid);
        transition accept;  
    }


    state parse_gtpv2 {
        packet.extract(hdr.gtpv2_ending);
        transition accept;
    }

/*
    state parse_gtpv1optional {
        packet.extract(hdr.gtpv1_optional);
        transition parse_inner_ipv4;
    }
*/

    state parse_inner1_ipv4 {
        packet.extract(hdr.inner1_ipv4);
        transition select(hdr.inner1_ipv4.protocol) {
            IPPROTO_TCP  : parse_inner1_tcp;
            default      : accept;
        }

     }   

    state parse_inner1_tcp {
        packet.extract(hdr.inner1_tcp);
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



    /***************************** Drop *****************************/

    action drop() {
        mark_to_drop();

    }

    action nop() {
       
    }

    /***************************** process mac learn  *****************************/

    action mac_learn() {
        digest(MAC_LEARN_RECEIVER, { hdr.ethernet.srcAddr, standard_metadata.ingress_port } );
    }
     

    table smac {
    key = {
        standard_metadata.ingress_port : exact;
        hdr.ethernet.srcAddr : exact;
    }
    actions = {mac_learn; }
    size = 512;
    default_action = mac_learn;
    }
    action arp_digest() {
        NoAction(); /*digest(ARP_LEARN_RECEIVER, */
    }

   
    /**********************************************************************************/


    action arp_reply() {
        hdr.ethernet.dstAddr = hdr.arp_ipv4.sha;
        hdr.ethernet.srcAddr = OWN_MAC;      
        hdr.arp.oper         = ARP_OPER_REPLY;
        hdr.arp_ipv4.tha     = hdr.arp_ipv4.sha;
        hdr.arp_ipv4.tpa     = hdr.arp_ipv4.spa;
        hdr.arp_ipv4.sha     = OWN_MAC;
        hdr.arp_ipv4.spa     = meta.arp_metadata.dst_ipv4;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action send_icmp_reply() {
        mac_addr_t   tmp_mac;
        ipv4_addr_t  tmp_ip;
        tmp_mac              = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp_mac;
        tmp_ip               = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr     = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr     = tmp_ip;
        hdr.icmp.type        = ICMP_ECHO_REPLY;
        hdr.icmp.checksum    = 0; // For now
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    /************** forwarding ipv4 *********************************************/


    action forward(port_id_t port) {
        standard_metadata.egress_spec = port;
	    hdr.ethernet.srcAddr = OWN_MAC;
    }

    action bcast() {
        standard_metadata.egress_spec = 100;
    }

    action pkt_send(mac_addr_t nhmac, port_id_t port) {
        hdr.ethernet.srcAddr = OWN_MAC; // simplified
        hdr.ethernet.dstAddr = nhmac;
        standard_metadata.egress_spec = port;
    }

   
    table dmac {
    key = {
        hdr.ethernet.dstAddr : exact;
    }
    actions = {forward; bcast;}
    size = 512;
    default_action = bcast;
}

    table ipv4_forward {
    key = {
        meta.routing_metadata.nhgrp : exact;        
    }
    actions = {pkt_send; drop;}
    size = 64;
    default_action = drop;
}


    /***************************** GTP Encapuslation *****************************/


    action gtp_encapsulate(bit<32> teid, bit<32> ip) {
       
        hdr.inner1_tcp.setValid();
        hdr.inner1_tcp = hdr.inner_tcp;
        hdr.inner_tcp.setInvalid();

        hdr.inner1_ipv4.setValid();
        hdr.inner1_ipv4 = hdr.inner_ipv4;
        
        hdr.gtp.setValid();
        hdr.gtp_teid.setValid();
        hdr.gtp_teid.teid = teid;
        hdr.gtp.version = 1;
        hdr.gtp.pFlag = 1;
        hdr.gtp.messageType = 0xff;
        hdr.gtp.messageLength = hdr.inner1_ipv4.totalLen + 8;


        hdr.inner_udp.setValid();
        hdr.inner_udp = hdr.udp;
        hdr.inner_udp.srcPort = GTP_UDP_PORT;
        hdr.inner_udp.dstPort = GTP_UDP_PORT;
        hdr.inner_udp.checksum = 0;
        hdr.inner_udp.plength = hdr.gtp.messageLength + 8;
        
         
        hdr.inner_ipv4.srcAddr = VIRTUAL_EPG_IP;
        hdr.inner_ipv4.dstAddr = VIRTUAL_DCGW_IP ;
        hdr.inner_ipv4.protocol = IPPROTO_UDP;
        hdr.inner_ipv4.hdrChecksum = 0;
        hdr.inner_ipv4.ihl = 5;
        hdr.inner_ipv4.totalLen = hdr.inner_udp.plength + 20;
        

        hdr.inner_ethernet.srcAddr = VIRTUAL_EPG_MAC;
        hdr.inner_ethernet.dstAddr = VIRTUAL_DCGW_MAC ;
        hdr.inner_ethernet.etherType = ETHERTYPE_IPV4; 


        hdr.udp.srcPort = 45149;
        hdr.udp.dstPort = 4789;
        hdr.udp.plength = hdr.inner_ipv4.totalLen + 14 + 16 ;
        hdr.udp.checksum = 0;

        hdr.ipv4.srcAddr = GW_IP;
        hdr.ipv4.dstAddr = ip;
        hdr.ipv4.ttl = 255;
        hdr.ipv4.totalLen = hdr.udp.plength + 20;
        hdr.ipv4.hdrChecksum = 0;
        meta.gtp_metadata.teid = teid;

        hdr.ethernet.setInvalid();
        hdr.ethernet.setValid();
        hdr.ethernet.etherType = ETHERTYPE_IPV4;
                     
    }


    /***************************** GTP Decapsulate *****************************/

    action gtp_decapsulate(ip4Addr_t ip) {
        
        
        hdr.inner_ipv4 = hdr.inner1_ipv4;
        hdr.inner1_ipv4.setInvalid();
        hdr.inner_udp.setInvalid();

        hdr.ipv4.srcAddr = GW_IP;
        hdr.ipv4.dstAddr = ip;

        hdr.inner_tcp.setValid();
        hdr.inner_tcp = hdr.inner1_tcp;
        hdr.inner1_tcp.setInvalid();

        meta.gtp_metadata.teid =  hdr.gtp_teid.teid;
        
        hdr.gtp.setInvalid();
        hdr.gtp_teid.setInvalid();
    
        hdr.ipv4.totalLen = 90;
        hdr.udp.plength = 70;

        }
    

    table vEPG_DL {
    key = {
        hdr.ipv4.dstAddr : lpm;
        hdr.udp.dstPort  : exact;
    }

    actions = { gtp_encapsulate; drop;}
    size = 10000;
    default_action = drop;

    
}
 
    table vEPG_UL {
    key = {
        hdr.ipv4.dstAddr : lpm;
        hdr.udp.dstPort  : exact;
    }

    actions = { gtp_decapsulate; drop;}
    size = 10000;
    default_action = drop;

    
}
    
    /*****************************************************************************/

    /***************************** Firewall_DL ***********************************/

    table firewall_DL {
    key = {
            hdr.inner1_ipv4.dstAddr  : exact;
    }

    actions = { drop; nop; }
    size = 128;
    default_action = nop();
    }
    
  
     /***************************** Firewall_UL ***********************************/

    table firewall_UL {
    key = {
            hdr.inner_ipv4.dstAddr : exact;
    }

    actions = { drop; nop; }
    size = 128;
    default_action = nop();
    }
    

     /*****************************************************************************/


    action set_nhgrp(bit<8> nhgrp) {
        meta.routing_metadata.nhgrp = nhgrp;
	    hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
    key = {
        hdr.ipv4.dstAddr : lpm;
    }
    actions = { set_nhgrp; drop; }
    size = 256;
    default_action = drop;
    }


    /********************************** Rate Limiter *****************************************/

    meter(256, MeterType.bytes) teid_meters;

    action apply_meter(bit<32> mid) {
        teid_meters.execute_meter(mid, meta.gtp_metadata.color ); // 0- Green, 1-Yellow, 2. Red
    }
    
    table teid_rate_limiter {
	key = {
		meta.gtp_metadata.teid : exact;
	}
	actions = { apply_meter; nop;}
	size = 256;
	default_action = nop;
    }


/************************************* Counter ***********************************/

    direct_counter(CounterType.packets_and_bytes) direct_port_counter;

    table count_table {

    key = {
        standard_metadata.ingress_port: exact ;
    }
    
    actions = {
    nop;
    }

    default_action = nop;
    counters = direct_port_counter;
    size = 512;

    }


/***********************************************************************************/


/*********************************************************************************/
/**************************** Apply **********************************************/
/*********************************************************************************/ 

apply {

	smac.apply();
	dmac.apply();
	count_table.apply();   

    if ( (hdr.ethernet.srcAddr == OWN_MAC) || (hdr.ethernet.srcAddr == BCAST_MAC) )
    
    {

    if ( hdr.ipv4.isValid() ) 

    {
        
    if (hdr.gtp.isValid())

    { vEPG_UL.apply(); }

    else  

    {vEPG_DL.apply();}

	ipv4_lpm.apply();
	ipv4_forward.apply();

    if (hdr.gtp.isValid())

    { firewall_DL.apply(); }

    else 

    { firewall_UL.apply(); } 


    teid_rate_limiter.apply();

    if (meta.gtp_metadata.color == METER_COLOR_RED) 
    { mark_to_drop ();
    }

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
     apply { /*
	   update_checksum(
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
            HashAlgorithm.csum16);
   */
        
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply { 

        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.arp_ipv4);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.udp);
        packet.emit(hdr.vxlan);
        packet.emit(hdr.inner_ethernet);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_udp);
        packet.emit(hdr.gtp);
        packet.emit(hdr.gtp_teid);
        packet.emit(hdr.inner1_ipv4);
        packet.emit(hdr.inner1_tcp);
    	
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

