/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_if.h"
#include "sr_utils.h"
#include "sr_router.h"

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

int sr_load_rt(struct sr_instance* sr,const char* filename)
{
    FILE* fp;
    char  line[BUFSIZ];
    char  dest[32];
    char  gw[32];
    char  mask[32];    
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;
    int clear_routing_table = 0;

    /* -- REQUIRES -- */
    assert(filename);
    if( access(filename,R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename,"r");

    while( fgets(line,BUFSIZ,fp) != 0)
    {
        sscanf(line,"%s %s %s %s",dest,gw,mask,iface);
        if(inet_aton(dest,&dest_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    dest);
            return -1; 
        }
        if(inet_aton(gw,&gw_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    gw);
            return -1; 
        }
        if(inet_aton(mask,&mask_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    mask);
            return -1; 
        }
        if( clear_routing_table == 0 ){
            printf("Loading routing table from server, clear local routing table.\n");
            sr->routing_table = 0;
            clear_routing_table = 1;
        }
        sr_add_rt_entry(sr,dest_addr,gw_addr,mask_addr,(uint32_t)0,iface);
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- sr_load_rt -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
int sr_build_rt(struct sr_instance* sr){
    struct sr_if* interface = sr->if_list;
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    while (interface){
        dest_addr.s_addr = (interface->ip & interface->mask);
        gw_addr.s_addr = 0;
        mask_addr.s_addr = interface->mask;
        strcpy(iface, interface->name);
        sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, (uint32_t)0, iface);
        interface = interface->next;
    }
    return 0;
}

void sr_add_rt_entry(struct sr_instance* sr, struct in_addr dest,
struct in_addr gw, struct in_addr mask, uint32_t metric, char* if_name)
{   
    struct sr_rt* rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    pthread_mutex_lock(&(sr->rt_lock));
    /* -- empty list special case -- */
    if(sr->routing_table == 0)
    {
        sr->routing_table = (struct sr_rt*)malloc(sizeof(struct sr_rt));
        assert(sr->routing_table);
        sr->routing_table->next = 0;
        sr->routing_table->dest = dest;
        sr->routing_table->gw   = gw;
        sr->routing_table->mask = mask;
        strncpy(sr->routing_table->interface,if_name,sr_IFACE_NAMELEN);
        sr->routing_table->metric = metric;
        time_t now;
        time(&now);
        sr->routing_table->updated_time = now;

        pthread_mutex_unlock(&(sr->rt_lock));
        return;
    }

    /* -- find the end of the list -- */
    rt_walker = sr->routing_table;
    while(rt_walker->next){
      rt_walker = rt_walker->next; 
    }

    rt_walker->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
    assert(rt_walker->next);
    rt_walker = rt_walker->next;

    rt_walker->next = 0;
    rt_walker->dest = dest;
    rt_walker->gw   = gw;
    rt_walker->mask = mask;
    strncpy(rt_walker->interface,if_name,sr_IFACE_NAMELEN);
    rt_walker->metric = metric;
    time_t now;
    time(&now);
    rt_walker->updated_time = now;
    
     pthread_mutex_unlock(&(sr->rt_lock));
} /* -- sr_add_entry -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_table(struct sr_instance* sr)
{
    pthread_mutex_lock(&(sr->rt_lock));
    struct sr_rt* rt_walker = 0;

    if(sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        pthread_mutex_unlock(&(sr->rt_lock));
        return;
    }
    printf("  <---------- Router Table ---------->\n");
    printf("Destination\tGateway\t\tMask\t\tIface\tMetric\tUpdate_Time\n");

    rt_walker = sr->routing_table;
    
    while(rt_walker){
        if (rt_walker->metric < INFINITY)
            sr_print_routing_entry(rt_walker);
        rt_walker = rt_walker->next;
    }
    pthread_mutex_unlock(&(sr->rt_lock));


} /* -- sr_print_routing_table -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_entry(struct sr_rt* entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);
    
    char buff[20];
    struct tm* timenow = localtime(&(entry->updated_time));
    strftime(buff, sizeof(buff), "%H:%M:%S", timenow);
    printf("%s\t",inet_ntoa(entry->dest));
    printf("%s\t",inet_ntoa(entry->gw));
    printf("%s\t",inet_ntoa(entry->mask));
    printf("%s\t",entry->interface);
    printf("%d\t",entry->metric);
    printf("%s\n", buff);

} /* -- sr_print_routing_entry -- */


void *sr_rip_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    while (1) {
        sleep(5);
        pthread_mutex_lock(&(sr->rt_lock));
        /* Fill your code here */
		
		
		/* check for expired entries */
		
		time_t now;
		time(&now);
		/* accomodate for first item expired */
		struct sr_rt* rt_list = 0;
		rt_list = sr->routing_table;
		while (rt_list->next) {
			if ((rt_list->next)->updated_time - now > 20) {
				/* entry expired */
				rt_list->next = (rt_list->next)->next;
			} else {
				rt_list = rt_list->next;
			}
		}
		/* send rip update (aka a response) */
		send_rip_response(sr);
        pthread_mutex_unlock(&(sr->rt_lock));
    }
    return NULL;
}

void send_rip_request(struct sr_instance *sr){
    /* Fill your code here */
	
	/* malloc packet */
	uint8_t* packet = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
	
	/* rip hdr */
	sr_rip_pkt_t* rip_hdr = (sr_rip_pkt_t*) (packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_udp_hdr_t));
	rip_hdr->command = 1;
	rip_hdr->version = 2;
	/* TODO: what to do with entries? */
	
	/* udp hdr */
	sr_udp_hdr_t* udp_hdr = (sr_udp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	udp_hdr->port_src = htons(520);
	udp_hdr->port_dst = htons(520);
	udp_hdr->udp_len = htons(sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
	udp_hdr->udp_sum = 0;
	udp_hdr->udp_sum = cksum(udp_hdr, udp_hdr->udp_len);
	
	/* ip hdr */
	sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_p = ip_protocol_udp;
	/* TODO: What IP source? */ 
	
	ip_hdr->ip_dst = ~(0x0);
	ip_hdr->ip_v = 4;
	ip_hdr->ip_off = htons(IP_DF);
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
	ip_hdr->ip_hl = 5;
	
	/* ethernet hdr */
	sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*) packet;
	ether_hdr->ether_type = htons(ethertype_ip);
	memset(ether_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
	/* TODO: What is source? */ 
	
	
	/* TODO: iterate through each interface and send out of all of them */
	struct sr_if* if_list =0;
	if_list = sr->if_list;
	
	while (if_list) {
		ip_hdr->ip_src = if_list->ip; 
		memcpy(ether_hdr->ether_shost, if_list->addr, ETHER_ADDR_LEN);
		ip_hdr->ip_sum = 0;
		ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
		print_hdrs(packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
		int success = sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t), if_list->name);
		if (success != 0) {
			printf("Error in sending RIP request.");
		} else {
			printf("RIP request sent.");
		}
		if_list = if_list->next;
	}
	free(packet);
	
	
	
	
}

void send_rip_response(struct sr_instance *sr) {
	
	/* Fill your code here */
		
		/* malloc packet */
		uint8_t* packet = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
		
		/* rip hdr */
		sr_rip_pkt_t* rip_hdr = (sr_rip_pkt_t*) (packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_udp_hdr_t));
		rip_hdr->command = 2;
		rip_hdr->version = 2;
		/* TODO: what to do with entries? */
		
		/* printing routing table */
		sr_print_routing_table(sr);
		/* TODO: Do I need these locks? */
		pthread_mutex_lock(&(sr->rt_lock));
		printf("Copying entries...\n");
		struct sr_rt* rt_list = 0;
		
		rt_list = sr->routing_table;
		int i;
		for (i = 0; i < 25; i++) {
			if (rt_list) {
				/* copy in entry */
				printf("Copying entry number %d...\n", i);
				(rip_hdr->entries[i]).address = rt_list->dest.s_addr;
				(rip_hdr->entries[i]).mask = rt_list->mask.s_addr;
				(rip_hdr->entries[i]).metric = rt_list->metric;
				(rip_hdr->entries[i]).next_hop = rt_list->gw.s_addr;
				rt_list = rt_list->next;
				/*struct entry* entry_copy = (struct entry*) malloc(sizeof(struct entry));*/
				/* TODO: Is this the right address? */
				/*entry_copy->address = rt_list->dest.s_addr;
				entry_copy->mask = rt_list->mask.s_addr;*/
				/* TODO: Next hop parameter? */
				/*entry_copy->next_hop = rt_list->gw.s_addr;
				entry_copy->metric = rt_list->metric;
				memcpy(&(rip_hdr->entries[i]), entry_copy, sizeof(struct entry)); */
			} else {
				printf("Making blank entry number %d...\n", i);
				
				(rip_hdr->entries[i]).address = 0x0;
				
				(rip_hdr->entries[i]).mask = 0x0;
				
				(rip_hdr->entries[i]).metric = htons(INFINITY);
				
				(rip_hdr->entries[i]).next_hop = 0x0;
				
				/* blank entry */
				/*struct entry* entry_copy = (struct entry*) malloc(sizeof(struct entry));
				entry_copy->address = 0x0;
				entry_copy->mask = 0x0;*/
				/* TODO: Next hop parameter? */
				/*entry_copy->next_hop = 0x0;
				entry_copy->metric = htons(INFINITY);
				memcpy(&(rip_hdr->entries[i]), entry_copy, sizeof(struct entry));*/
			}
			printf("Finished entry number %d...\n", i);
			
		}
		printf("Done copying entries...\n");
		pthread_mutex_unlock(&(sr->rt_lock));
		
		
		printf("Making UDP hdr...\n");
		/* udp hdr */
		sr_udp_hdr_t* udp_hdr = (sr_udp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		udp_hdr->port_src = htons(520);
		udp_hdr->port_dst = htons(520);
		udp_hdr->udp_len = sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t);
		udp_hdr->udp_sum = 0;
		udp_hdr->udp_sum = cksum(udp_hdr, udp_hdr->udp_len);
		printf("Making IP hdr...\n");
		/* ip hdr */
		sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
		ip_hdr->ip_ttl = 64;
		ip_hdr->ip_p = ip_protocol_udp;
		/* TODO: What IP source? */
		ip_hdr->ip_hl = 5;
		
		ip_hdr->ip_dst = ~(0x0);
		ip_hdr->ip_v = 4;
		ip_hdr->ip_off = htons(IP_DF);
		ip_hdr->ip_tos = 0;
		ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
		
		printf("Making Ethernet hdr...\n");
		/* ethernet hdr */
		sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*) packet;
		ether_hdr->ether_type = htons(ethertype_ip);
		memset(ether_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
		/* TODO: What is source? */
		
		
		/* TODO: iterate through each interface and send out of all of them */
		struct sr_if* if_list =0;
		if_list = sr->if_list;
		printf("Iterating through interfaces...\n");
		while (if_list) {
			memcpy(ether_hdr->ether_shost, if_list->addr, ETHER_ADDR_LEN);
			ip_hdr->ip_src = if_list->ip;
			ip_hdr->ip_sum = 0;
			ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
			print_hdrs(packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
			int success = sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t), if_list->name);
			if (success != 0) {
				printf("Error in sending RIP response.");
			} else {
				printf("RIP response sent.");
			}
			if_list = if_list->next;
		}
		free(packet);
		
	
}

void send_rip_update(struct sr_instance *sr){
    pthread_mutex_lock(&(sr->rt_lock));
    /* Fill your code here */

    pthread_mutex_unlock(&(sr->rt_lock));
}

void update_route_table(struct sr_instance *sr, sr_ip_hdr_t* ip_packet, sr_rip_pkt_t* rip_packet, char* iface){
    pthread_mutex_lock(&(sr->rt_lock));
    /* Fill your code here */
    int change_made = 0;
    /*need to compare routing tables*/
    sr_print_routing_table(sr);

    printf("Comparing routing table entries...\n");
    struct sr_rt* sr_entry = sr->routing_table;
    int entry_found = 0;
    int i;
    for (i = 0; i < MAX_NUM_ENTRIES; i++) { /* for each entry in pkt */
        struct entry *current_entry = &(rip_packet->entries[i]); /* grab the entry */
        entry_found = 0;
        sr_entry = sr->routing_table;
        while (sr_entry && (entry_found == 0)) { /* compare it with every entry in routing table */
            /*if dest addr are a match*/
            if (current_entry->address == sr_entry->dest.s_addr) {
            	/* update time */
            	time_t now;
            	time(&now);
            	sr_entry->updated_time = now;
            	/*if metric of the rip packet is lower then update the routing table, metric and next_hop*/
                if ((current_entry->metric +1) < sr_entry->metric) {
                    printf("Found lower cost\n");
                    printf("Current metric:%d\nLower metric:%d\n", (current_entry->metric +1), sr_entry->metric);
                    sr_entry->metric = current_entry->metric + 1;
                    /*
                    struct in_addr ip_hop;
                    ip_hop.s_addr = ip_packet->ip_src;
                    struct sr_rt* next_hop_ip = search_rt(sr, ip_hop); */
                    sr_entry->gw.s_addr = ip_packet->ip_src;
                    change_made = 1;
                }
                entry_found = 1;
            }
            sr_entry = sr_entry->next;            
        }
        /*if no match was found*/
        if (!entry_found) {
           struct in_addr new_addr;
           new_addr.s_addr = current_entry->address;
           struct in_addr new_gw;
           new_gw.s_addr = current_entry->next_hop;
           struct in_addr new_mask;
           new_mask.s_addr = current_entry->mask;
           sr_add_rt_entry(sr, new_addr, new_gw, new_mask, current_entry->metric + 1, iface);
           send_rip_response(sr);
           change_made = 1;
        }
    }
    if (change_made) {
    	/*need to send a rip response*/
    	printf("Sending RIP Response");
    	send_rip_response(sr);
    }
    pthread_mutex_unlock(&(sr->rt_lock));
}


