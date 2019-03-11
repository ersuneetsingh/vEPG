#include "controller.h"
#include "messages.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>


controller c;

uint8_t macs[MAX_MACS][6];
uint8_t macd[MAX_MACS][6];
uint8_t portmap[MAX_MACS];
uint8_t ips[MAX_MACS][4];
uint8_t ipd1[MAX_MACS][4];
uint8_t ipd2[MAX_MACS][4];
uint8_t ipd_inner[MAX_MACS][4];
uint8_t teid[MAX_MACS]
int mac_count = -1;
uint8_t stcp_txt[MAX_MACS][2];
uint8_t ips_new[MAX_MACS][4];


int read_macs_and_ports_from_file(char *filename) {
    FILE *f;
    char line[200];
    int values1[6];
    int values2[6];
    int values_ip1[4];
    int values_ip2[4];
    int values_ip3[4];
    int teid1;
    int i;
    
    f = fopen(filename, "r");
    if (f == NULL) return -1;
    
    while (fgets(line, sizeof(line), f)) {
        line[strlen(line)-1] = '\0';
        //TODO why %c?
        if (25 == sscanf(line, "%x:%x:%x:%x:%x:%x %d.%d.%d.%d %d.%d.%d.%d %x:%x:%x:%x:%x:%x %d.%d.%d.%d %d",
                         &values1[0], &values1[1], &values1[2],
                         &values1[3], &values1[4], &values1[5], &values_ip1[0], &values_ip1[1], &values_ip1[2], &values_ip1[3], &values_ip2[0], &values_ip2[1], &values_ip2[2], &values_ip2[3], &values2[0], &values2[1], &values2[2],
                         &values2[3], &values2[4], &values2[5], &values_ip3[0], &values_ip3[1], &values_ip3[2], &values_ip3[3]
                         , &teid1) )
        {
            if (mac_count==MAX_MACS-1)
            {
                printf("Too many entries...\n");
                break;
            }
            
            ++mac_count;
            for( i = 0; i < 6; ++i )
                macs[mac_count][i] = (uint8_t) values1[i];
            for( i = 0; i < 4; ++i )
                ipd1[mac_count][i] = (uint8_t) values_ip1[i];
            for( i = 0; i < 4; ++i )
                ipd2[mac_count][i] = (uint8_t) values_ip2[i];
            for( i = 0; i < 6; ++i )
                macd[mac_count][i] = (uint8_t) values2[i];
            for( i = 0; i < 4; ++i )
                ipd_inner[mac_count][i] = (uint8_t) values_ip3[i];
            teid[mac_count][1] = (unit8_t) teid1;
           
            
           // portmap[mac_count] = (uint8_t) port;
            
        } else {
            printf("Wrong format error in line %d : %s\n", mac_count+2, line);
            fclose(f);
            return -1;
        }
        
    }
    
    fclose(f);
    return 0;
}

void fill_smac(uint8_t mac[6] )
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    
    struct p4_field_match_exact* exact;
    printf("fill_smac table update \n");
    
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "smac");
    
    
    exact = add_p4_field_match_exact(te, 2048);
    strcpy(exact->header.name, "hdr.ethernet.srcAddr"); // key
    memcpy(exact->bitmap, mac, 6);
    exact->length = 6*8+0;
    
    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "mac_learn");
    
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);
    send_p4_msg(c, buffer, 2048);
    printf("########## fill smac table \n");
    printf("\n");
    printf("Table name: %s\n", te->table_name);
    printf("Action: %s\n", a->description.name);
    
}

void fill_dmac(uint8_t mac[6], unit8_t port)
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap;
    
    
    struct p4_field_match_exact* exact;
    printf("fill_dmac table update \n");
    
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "dmac");
    
    
    exact = add_p4_field_match_exact(te, 2048);
    strcpy(exact->header.name, "hdr.ethernet.dstAddr"); // key
    memcpy(exact->bitmap, mac, 6);
    exact->length = 6*8+0;
    
    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "forward");
    
    ap = add_p4_action_parameter(h, a, 2048);
    strcpy(ap->name, "port");
    ap->bitmap[0] = port;
    ap->bitmap[1] = 0;
    ap->length = 2*8+0;
    
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);
    send_p4_msg(c, buffer, 2048);
    printf("########## fill dmac table \n");
    printf("\n");
    printf("Table name: %s\n", te->table_name);
    printf("Action: %s\n", a->description.name);
    
}

void fill_vEPG_UL(uint8_t dst_ip1[4], unit8_t dst_ip2[4])
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap;
    
    
    struct p4_field_match_exact* exact;
    printf("fill_vEPG_UL table update \n");
    
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "vEPG_UL");
    
    
    exact = add_p4_field_match_exact(te, 2048);
    strcpy(exact->header.name, "hdr.ipv4.dstAddr"); // key
    memcpy(exact->bitmap, ip1, 4);
    exact->length = 4*8+0;
    
    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "gte_decapsulate");
    
    ap = add_p4_action_parameter(h, a, 2048);
    strcpy(ap->name, "ip");
    memcpy(ap->bitmap, ip2, 4);
    ap->length = 4*8+0;
    
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);
    send_p4_msg(c, buffer, 2048);
    printf("########## fill vEPG_UL table \n");
    printf("\n");
    printf("Table name: %s\n", te->table_name);
    printf("Action: %s\n", a->description.name);
    
}

void fill_ipv4_lpm(uint8_t dst_ip[4], unit8_t nhgrp)
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap;
    
    
    struct p4_field_match_exact* exact;
    printf("fill_ipv4_lpm table update \n");
    
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "ipv4_lpm");
    
    
    exact = add_p4_field_match_exact(te, 2048);
    strcpy(exact->header.name, "hdr.ipv4.dstAddr"); // key
    memcpy(exact->bitmap, ip, 4);
    exact->length = 4*8+0;
    
    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "set_nhgrp");
    
    ap = add_p4_action_parameter(h, a, 2048);
    strcpy(ap->name, "nhgrp");
    memcpy(ap->bitmap, nhgrp);
    ap->length = 1*8+0;
    
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);
    send_p4_msg(c, buffer, 2048);
    printf("########## fill ipv4_lpm table \n");
    printf("\n");
    printf("Table name: %s\n", te->table_name);
    printf("Action: %s\n", a->description.name);
    
}

void fill_ipv4_forward(uint8_t nhgrp, unit8_t nhmac[6], unit8_t port)
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap;
    

    struct p4_field_match_exact* exact;
    printf("fill_ipv4_forward table update \n");
    
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "ipv4_forward");
    
    exact = add_p4_field_match_exact(te, 2048);
    strcpy(exact->header.name, "meta.routing_metadata.nhgrp"); // key
    memcpy(exact->bitmap, nhgrp);
    exact->length = 1*8+0;
    
    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "set_nhgrp");
    
    ap = add_p4_action_parameter(h, a, 2048);
    strcpy(ap->name, "nhgrp");
    memcpy(ap->bitmap, nhgrp);
    ap->length = 1*8+0;
    
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);
    send_p4_msg(c, buffer, 2048);
    printf("########## fill ipv4_forward table \n");
    printf("\n");
    printf("Table name: %s\n", te->table_name);
    printf("Action: %s\n", a->description.name);
    
}

void fill_firewall_UL(uint8_t ip[4])
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap;
    
    
    struct p4_field_match_exact* exact;
    printf("fill_firewall_UL table update \n");
    
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "firewall_UL");
    
    exact = add_p4_field_match_exact(te, 2048);
    strcpy(exact->header.name, "hdr.inner_ipv4.dstAddr"); // key
    memcpy(exact->bitmap, nhgrp);
    exact->length = 1*8+0;
    
    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "drop");
    
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);
    send_p4_msg(c, buffer, 2048);
    printf("########## fill firewall_UL table \n");
    printf("\n");
    printf("Table name: %s\n", te->table_name);
    printf("Action: %s\n", a->description.name);
    
}

void fill_teid_rate_limiter(uint8_t teid)
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap;
    
    
    struct p4_field_match_exact* exact;
    printf("fill_teid_rate_limiter table update \n");
    
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "teid_rate_limiter");
    
    exact = add_p4_field_match_exact(te, 2048);
    strcpy(exact->header.name, "meta.gtp_metadata.teid"); // key
    memcpy(exact->bitmap, teid);
    exact->length = 1*8+0;
    
    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "apply_meter");
    
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);
    send_p4_msg(c, buffer, 2048);
    printf("########## fill teid_rate_limiter table \n");
    printf("\n");
    printf("Table name: %s\n", te->table_name);
    printf("Action: %s\n", a->description.name);
    
}

void dhf(void* b) {
    printf("Unknown digest received\n");
}


void init() {
   
    //printf("Set default actions.\n");
    int i;
    //uint8_t smac[6] = {0xd0, 0x69, 0x0f, 0xa8, 0x39, 0x90};
    uint8_t dmac[6] = {0xd0, 0x69, 0x0f, 0xa8, 0x39, 0x90};
    uint8_t ipd_epg[4] = {192,168,0,1};
    uint8_t ipd_dcgw[4] = {192,168,0,2};
    unit8_t nhgrp = 2;
    
    
    unit8_t in_port =  0;
    unit8_t out_port = 1;
    printf("INIT");
    //TODO
    //printf("Set default actions.\n");
    //set_default_action_smac();
    //set_default_action_dmac();
    
    fill_dmac(dmac, out_port);
    

    
    for (i=0;i<=mac_count;++i)
    {
        printf("Filling tables lpm_table/sendout_table MAC: %02x:%02x:%02x:%02x:%02x:%02x IP: %d.%d.%d.%d\n", macs[i][0],macs[i][1],macs[i][2],macs[i][3],macs[i][4],macs[i][5], ipd1[i][0],ipd1[i][1],ipd1[i][2],ipd1[i][3], ipd2[i][0],ipd2[i][1],ipd2[i][2],ipd2[i][3], macd[i][0],macd[i][1],macd[i][2],macd[i][3],macd[i][4],macd[i][5],ipd_inner[i][0],ipd_inner[i][1],ipd_inner[i][2],ipd_inner[i][3], teid[i]);
        
        fill_smac(macs[i]);
        fill_vEPG_UL(ipd1[i], ipd2[i]);
        fill_ipv4_lpm(ipd2[i], nhgrp);
        fill_ipv4_forward( nhgrp, macd[i], out_port);
        fill_firewall_UL(ipd_inner[i]);
        fill_teid_rate_limiter(teid[i]);
        usleep(10000);
    }
    
    printf ("ctrl Total entries sent %d\n",i);
    
}


int main(int argc, char* argv[])
{
    if (argc>1) {
        if (argc!=2) {
            printf("Too many arguments...\nUsage: %s <filename(optional)>\n", argv[0]);
            return -1;
        }
        printf("Command line argument is present...\nLoading configuration data...\n");
        if (read_macs_and_ports_from_file(argv[1])<0) {
            printf("File cannnot be opened...\n");
            return -1;
        }
    }
    
    printf("Create and configure controller...\n");
    c = create_controller_with_init(11111, 3, dhf, init);
    printf("MACSAD controller started...\n");
    execute_controller(c);
    
    printf("MACSAD controller terminated\n");
    destroy_controller(c);
    return 0;
    }
