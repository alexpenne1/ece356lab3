/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

void sr_handlearp(struct sr_instance* sr, uint8_t* arp_buffer, char* interface, unsigned int len);
void send_arp_reply(struct sr_instance* sr, sr_arp_hdr_t* arp_packet, char* interface);
void sr_handle_ip(struct sr_instance* sr, uint8_t* packet, char* ip_interface, unsigned int ip_len, unsigned int packet_len);
int send_icmp_exception(struct sr_instance* sr, uint8_t type, uint8_t code, uint8_t* packet, uint8_t* buf, struct sr_if* interface);
int send_icmp_reply(struct sr_instance* sr, uint8_t type, uint8_t code, uint8_t* packet, struct sr_if* interface, unsigned int len);
struct sr_rt* search_rt(struct sr_instance* sr, struct in_addr addr);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t arp_thread;

    pthread_create(&arp_thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    srand(time(NULL));
    pthread_mutexattr_init(&(sr->rt_lock_attr));
    pthread_mutexattr_settype(&(sr->rt_lock_attr), PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(sr->rt_lock), &(sr->rt_lock_attr));

    pthread_attr_init(&(sr->rt_attr));
    pthread_attr_setdetachstate(&(sr->rt_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t rt_thread;
    pthread_create(&rt_thread, &(sr->rt_attr), sr_rip_timeout, sr);
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

/* SR_HANDLEPACKET */
/* Incoming packet goes here and is determined to be IP or ARP. */
/* Packet forwarded to handle_x_type method. */

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  if (len < sizeof(sr_ethernet_hdr_t)) {
  	  printf("Incoming packet too small.\n");
  	  return;
  }
  print_hdrs(packet, len);
  /* Determine if IP or ARP packet from ethertype. (found in sr_protocol.h) */
  switch (ethertype(packet)) {
  case ethertype_ip:
  	printf("Packet is IP..\n");
  	sr_handle_ip(sr, packet, interface, len-sizeof(sr_ethernet_hdr_t), len);
  	break;
  case ethertype_arp:
  	printf("Packet is ARP.\n");
  	sr_handlearp(sr, packet + sizeof(sr_ethernet_hdr_t), interface, len - sizeof(sr_ethernet_hdr_t));
  	break;
  default:
  	printf("Unknown ethertype.\n");
  	return;
  } /* end switch */
} /* end sr_handlepacket */

/* SR_HANDLEARP */
/* Handles all ARP packets. Requests send a reply, replies add to cache. */
 

void sr_handlearp(struct sr_instance* sr, uint8_t* arp_buffer, char* interface, unsigned int len) {
	/* Cast buffer to arp header struct type. */
	sr_arp_hdr_t* arp_packet = (sr_arp_hdr_t*) arp_buffer;
	enum sr_arp_opcode opcode = (enum sr_arp_opcode)ntohs(arp_packet->ar_op);
	/* Determine if request or reply. */
	switch (opcode) {
	case arp_op_request:
		printf("ARP request.\n");
		send_arp_reply(sr, arp_packet, interface); /* DONE */
		break;
	case arp_op_reply:
		printf("ARP reply.\n");
		  
		struct sr_arpreq* request = sr_arpcache_insert(&(sr->cache), arp_packet->ar_sha, arp_packet->ar_sip);
		printf("Checking if in queue...\n");
		if (request) {
			printf("Sending packets waiting in queue.\n");
			struct sr_packet* packets = request->packets;
			struct sr_arpentry* cache_entry;
			while (packets) {
				printf("Sending packet.\n");
				cache_entry = sr_arpcache_lookup(&(sr->cache), request->ip);
				if (cache_entry) {
					printf("Found cache entry.\n");
					printf("Sending ICMP packet:\n");
					sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*) packets->buf;
					  memcpy(ether_hdr->ether_dhost, arp_packet->ar_sha, ETHER_ADDR_LEN); 
					  struct sr_if* iface = sr_get_interface(sr, interface);
					  memcpy(ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
					  ether_hdr->ether_type = htons(ethertype_ip);
					  
					  print_hdrs(packets->buf, packets->len);
					  
					  
					  
					  int success = sr_send_packet(sr, packets->buf, packets->len, packets->iface);
					  if (success!= 0) {
						  printf("Error in sending packet.\n");
					  } else {
						  printf("Sent packet.\n");
						  
					  }
					  packets=packets->next;
				  } else {
					  printf("Queueing the request again.\n");
					  
				  }
				  free(cache_entry);
			  }
			  sr_arpreq_destroy(&sr->cache, request);
			  
		  } else {
		  printf("No requests found matching arp reply.\n"); }
		  
		  break;
	default:
		printf("Unknown ARP opcode: %hx\n", arp_packet->ar_op);
		/* put into cache */
		sr_arpcache_insert(&sr->cache, arp_packet->ar_sha, arp_packet->ar_sip);
		return;
	} /* end switch */
} /* end handle arp */


/* SEND_ARP_REPLY */
/* Sends ARP replies when a request is sent. */
void send_arp_reply(struct sr_instance* sr, sr_arp_hdr_t* arp_packet, char* interface) {
	/* Malloc header space. */
	printf("Sending arp reply...\n");
	uint8_t* mem_block = (uint8_t*) malloc(sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t));
	sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(mem_block+sizeof(sr_ethernet_hdr_t));
	sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)mem_block;
	struct sr_if* ifacestruct = (struct sr_if*) interface;
	struct sr_if* iface = sr_get_interface(sr, ifacestruct->name);
	/* ARP header: */
	arp_header->ar_op = htons(arp_op_reply); /* arp reply optype */
	arp_header->ar_hrd = htons(arp_hrd_ethernet); /*  ethernet hardware */
	arp_header->ar_hln = ETHER_ADDR_LEN; /* hardware address length */
	arp_header->ar_pro = htons(0x0800); /* protocol type (IPv4) */
	arp_header->ar_pln = sizeof(uint32_t); /* IPv4 length is 32 bits */
	arp_header->ar_sip = iface->ip; /* put own ip into source ip */
	arp_header->ar_tip = arp_packet->ar_sip; /* put source ip from request into target ip */
	memcpy(arp_header->ar_sha, iface->addr, ETHER_ADDR_LEN); /* put source ethernet address */
	memcpy(arp_header->ar_tha, arp_packet->ar_sha, ETHER_ADDR_LEN); /* put target ethernet address */

	/* Ethernet header: */
	memcpy(ethernet_header->ether_shost, iface->addr, ETHER_ADDR_LEN); /* Put in ethernet source and target MAC. */
	memcpy(ethernet_header->ether_dhost, arp_packet->ar_sha, ETHER_ADDR_LEN);
	ethernet_header->ether_type = htons(ethertype_arp);
	/* print source and dest */
	

	/* Try to send packet. */
	printf("Trying to send...\n");
	int success = sr_send_packet(sr, mem_block, sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t), iface->name);
	printf("ARP Sent.\n");
	print_hdrs(mem_block, sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t));
	if (success!=0) {
		printf("sr_send_packet error when trying to send ARP reply.\n");
	} 
	free(mem_block);

} /* end send arp reply */

/* SR_MATCH_INTERFACE */
/* Looks for interface in interface list. */

struct sr_if* sr_match_interface(struct sr_instance* sr, uint32_t ip) {
	struct sr_if* interface_match = sr->if_list;
	while(interface_match) {
		if (interface_match->ip == ip) {
			return interface_match;
		}
		interface_match = interface_match->next;
	}
	return 0;
}

/* SR_HANDLE_IP */
/* Handles all IP packets.*/

void sr_handle_ip(struct sr_instance* sr, uint8_t* packet, char* ip_interface, unsigned int ip_len, unsigned int packet_len) {

  
  /*uint8_t* ip_buffer = packet+sizeof(sr_ethernet_hdr_t);*/
  sr_ip_hdr_t* ip_packet = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
  
  
  /* check length */
  if (ip_len < sizeof(sr_ip_hdr_t)) {
	  printf("Packet length too small. Discarding.\n");
	  return;
  }
  
  
  /* check checksum */
  uint16_t incoming_checksum = ntohs(ip_packet-> ip_sum);
  ip_packet->ip_sum = 0; /* checksum not included */
  uint16_t calculated_checksum = ntohs(cksum(ip_packet, sizeof(sr_ip_hdr_t)));
  
  if (incoming_checksum != calculated_checksum) {
	  printf("Checksum is invalid. Discarding packet.\n");
	  return;
  } else {
	  printf("IP checksum valid.\n");
  }
  
  /* check ttl */
    if (ip_packet->ip_ttl < 1) {
  	  printf("Packet timed out. TTL <= 1. \n");
  	  send_icmp_reply(sr, 11, 0, packet, (struct sr_if *)ip_interface, 0); /*time exceeded*/
  	  return;
    } else {
    	printf("IP TTL valid.\n");
  	  
    }
    
    
  
  /* check if address is within network (sr_if.c/h) <- instance at member if_list */
  /*struct sr_if* interface_check = sr_get_interface(sr, ip_interface->name);*/
  
  
  
  struct sr_if* interface_check = sr_match_interface(sr, ip_packet->ip_dst);
  
  
  if (interface_check || (ip_packet->ip_dst == ~(0x0))) { /*in local interface*/
    
    
    
    if (ip_packet->ip_p == ip_protocol_icmp) { /*TO-DO: if ICMP echo request, checksum, then echo reply to the sending host */
    	
    	printf("IP is echo request.\n");
    	
    	send_icmp_reply(sr, 0, 9, packet, (struct sr_if*)ip_interface, packet_len);
    }
    else { 
    	/* check protocol of ip packet */
    	uint8_t incoming_ip_proto = ip_packet->ip_p;
    	if (incoming_ip_proto == ip_protocol_udp) {
    		printf("Is UDP packet.\n");
    		
    		sr_udp_hdr_t* incoming_udp_packet = (sr_udp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    		
    		/* TODO: Is packet RIP or other UDP? */
    		uint16_t port_dst = incoming_udp_packet->port_dst;
    		uint16_t port_src = incoming_udp_packet->port_src;
    		printf("Des port: %d\nSrc Port: %d\n", htons(port_dst), htons(port_src));
    		if (port_dst == htons(520) && port_src == htons(520)) {
    			printf("Is RIP packet.\n");
    			
    			sr_rip_pkt_t* incoming_rip_packet = (sr_rip_pkt_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
    			uint8_t command = incoming_rip_packet->command;
    			printf("Command: %d\n", command);
    			if (command == 2) {
    				printf("RIP response.\n");
    				update_route_table(sr, ip_packet, incoming_rip_packet, ip_interface);
    				/* TODO: implement update_route_table */
    				
    			} else if (command == 1){
    				printf("RIP request.\n");
    				send_rip_response(sr);
    				/* TODO: implement send RIP response */
    			} else {
    				printf("Unknown command.\n");
    				return;
    			}
    		} else {
    			printf("Is not RIP packet, sending exception.\n");
    			send_icmp_reply(sr, 3, 3, packet, (struct sr_if*)ip_interface, 0);
    		}
    		
    	} else {
    		printf("Is TCP, sending exception.\n");
    		send_icmp_reply(sr, 3, 3, packet, (struct sr_if*)ip_interface, 0); /*send an exception is UDP or TCP payload is sent to one of the interfaces*/
    	}
    	
    	
    } 
  } 
  /*if not within network/destined elsewhere*/
  else {
	  if (ip_packet->ip_ttl < 2) {
	    	  printf("Packet timed out. TTL <= 1. \n");
	    	  send_icmp_reply(sr, 11, 0, packet, (struct sr_if *)ip_interface, 0); /*time exceeded*/
	    	  return;
	  }
	  uint8_t* fwd_packet = (uint8_t*)malloc(packet_len);
	  int j;
	  for (j = 0; j < packet_len; j++) {
		  fwd_packet[j] = packet[j];
	  }
	  
	  ip_packet = (sr_ip_hdr_t*) (fwd_packet + sizeof(sr_ethernet_hdr_t));
	  ip_packet->ip_ttl = ip_packet->ip_ttl - 1;
	  ip_packet->ip_sum = 0;
	  ip_packet->ip_sum = cksum((uint8_t*)ip_packet, sizeof(sr_ip_hdr_t));
      /*find out which entry in the routing table has the longest prefix match with the destination IP address*/
      printf("Loading routing table from server.\n");
      struct in_addr ip_check;
      ip_check.s_addr = ip_packet->ip_dst;
      struct sr_rt* next_hop_ip = search_rt(sr, ip_check);
      
      if (next_hop_ip == 0) {
        printf("Next hop not found.\n");
        send_icmp_reply(sr, 3, 0, packet, (struct sr_if*)ip_interface, 0); /*port unreachable*/
        return; /*discard packet*/
      }
      struct sr_if* next_hop_interface = sr_get_interface(sr, next_hop_ip->interface);
      /*check arp cache for the next MAC address corresponding to the next-hop IP */
      printf("Searching for next hop MAC address.\n");
      uint32_t nh_addr = 0;
      if (next_hop_ip->gw.s_addr == 0) {
    	  nh_addr = ip_packet->ip_dst;
      } else {
    	  nh_addr = next_hop_ip->gw.s_addr;
      }
      
      sr_print_routing_table(sr);
      printf("Next hop address: %d\n", (nh_addr));
      struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, nh_addr);
      if (entry) { /* found entry */
    	  printf("Entry found. Forwarding packet.\n");
    	  sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) fwd_packet;
    	  memcpy(ethernet_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
    	  memcpy(ethernet_header->ether_shost, next_hop_interface->addr, ETHER_ADDR_LEN);
    	  
    	  int success = sr_send_packet(sr, fwd_packet, packet_len, next_hop_ip->interface);
    	  printf("FORWARDING ICMP PACKET\n\n\n");
    	  print_hdrs(fwd_packet, packet_len);
    	  if (success == 0) {
    		  printf("Forwarded successfully.");
    	  } else {
    		  printf("Error in forwarding packet.");
    	  }
      } else {
    	  printf("No entry found. Adding this packet to queue:\n");
    	  print_hdr_ip((uint8_t*)ip_packet);
    	  sr_arpcache_queuereq(&sr->cache, nh_addr, fwd_packet, packet_len, next_hop_ip->interface); /*i'm assuming that sr_arpcache_sweepreqs handles everything */ 
      }	
  } 
} 

/* SEARCH_RT */
/* Search through routing table to get DEST IP */
struct sr_rt* search_rt(struct sr_instance* sr, struct in_addr addr) {

  struct sr_rt* walker = sr->routing_table;
  struct sr_rt* best_match = NULL;
  uint32_t match_check = 0;

  while (walker != 0) { /*check if match*/
    if ((addr.s_addr & walker->mask.s_addr) == (walker->dest.s_addr & walker->mask.s_addr)) { /*check network address and destination address are a match*/
      if(!best_match || walker->mask.s_addr >= match_check) {
        match_check = walker->mask.s_addr;
        best_match = walker;
      }
    }
    walker = walker->next;
  }
  return best_match;
}

/* SEND_ICMP_REPLY */
/* Sends ICMP replies of all types */
int send_icmp_reply(struct sr_instance* sr, uint8_t type, uint8_t code, uint8_t* packet, struct sr_if* interface, unsigned int len) {
	
	sr_ip_hdr_t* incoming_ip_hdr = (sr_ip_hdr_t*) (packet+sizeof(sr_ethernet_hdr_t));
	sr_icmp_hdr_t* incoming_icmp_hdr = 0;
	if (type == 0) {
		incoming_icmp_hdr = (sr_icmp_hdr_t*) (packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
	}
	
	unsigned int icmp_len = 0;
	unsigned int total_size = 0;
	switch (type) {
	case(3):
			printf("ICMP is Type 3.\n");
			icmp_len = sizeof(sr_icmp_t3_hdr_t)+ htons(incoming_ip_hdr->ip_len);
			total_size = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+icmp_len;
			break;
	case(11):
			printf("ICMP is Type 11.\n");
			icmp_len = sizeof(sr_icmp_t3_hdr_t) + htons(incoming_ip_hdr->ip_len);
			total_size = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+icmp_len;
			break;
	
	default:
			printf("ICMP is NOT Type 3 or 11.\n");
			printf("Incoming length: %d\n", len);
			icmp_len = sizeof(sr_icmp_hdr_t);
			total_size = len;
			break;
	}
	
	uint8_t* client_memory = (uint8_t*) malloc(total_size);
	
	
	
	/*memcpy(ip_header, incoming_ip_hdr, ntohs(incoming_ip_hdr->ip_len));*/
	/* type == 3*/
	if (type == 3 || type == 11) {
		sr_icmp_t3_hdr_t* icmp_t3_hdr = (sr_icmp_t3_hdr_t*) (client_memory + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		icmp_t3_hdr->icmp_type = type;
		icmp_t3_hdr->next_mtu = 0;
		icmp_t3_hdr->unused = 0;
		
		
		/*memcpy(icmp_t3_hdr->data, packet+sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);*/
		/*
		memcpy(icmp_t3_hdr + sizeof(sr_icmp_t3_hdr_t), incoming_ip_hdr, htons(incoming_ip_hdr->ip_len));
		*/
		
		int i;
		for (i = 0; i < ICMP_DATA_SIZE; i++) {
			icmp_t3_hdr->data[i] = *((uint8_t*) incoming_ip_hdr + i);
		}
		
		
		
		if (code ==  0) {
		printf("Destination net unreachable or TTL.\n");
		
		}
		if (code == 1) {
		printf("Destination host unreachable\n");
		
		}
		if (code == 3) {
		printf("Port unreachable\n");
		
		}
		
		
		icmp_t3_hdr->icmp_code = code;
		if (type==0) {
			icmp_t3_hdr->icmp_code = 0;
		}
		icmp_t3_hdr->icmp_sum = 0;
		icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, icmp_len);


	/*if (type == 11) {
		icmp_t3_hdr->icmp_type = 11;
 		icmp_t3_hdr->icmp_code = 0;
	}*/
	} else {
		
		int k;
		for (k=0; k<len; k++) {
			client_memory[k] = packet[k];
		}
		
		sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*) (client_memory + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		icmp_hdr->icmp_type = type;
		icmp_hdr->icmp_code = 0;
		/*memcpy(icmp_hdr+sizeof(sr_icmp_hdr_t), incoming_ip_hdr, htons(incoming_ip_hdr->ip_len));*/
		icmp_hdr->icmp_sum = 0;
		icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
	}
	
	sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)client_memory;
		sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(client_memory+sizeof(sr_ethernet_hdr_t));
		/* populate ethernet header */
		struct in_addr ip_check;
		ip_check.s_addr = incoming_ip_hdr->ip_src;
		struct sr_rt* routing_table_entry = search_rt(sr, ip_check);
		struct sr_if* iface = sr_get_interface(sr, routing_table_entry->interface);
	

  /*populate ip head*/
	if (type != 0) {
		ip_header->ip_hl = 5;
			ip_header->ip_id = htons(incoming_ip_hdr->ip_id)+1;
			ip_header->ip_off = htons(IP_DF);
			ip_header->ip_v = 4;
			ip_header->ip_tos = 0;
			ip_header->ip_ttl = 64;
			ip_header->ip_p = ip_protocol_icmp;
			ip_header->ip_src = iface->ip;
			ip_header->ip_dst = incoming_ip_hdr->ip_src;
		
	} else { 
		
			ip_header->ip_tos = 0;
			ip_header->ip_ttl = 64;
			ip_header->ip_p = ip_protocol_icmp;
			ip_header->ip_src = iface->ip;
			ip_header->ip_dst = incoming_ip_hdr->ip_src;
	}
	
	if (type !=0) {
		ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + icmp_len);
	}
	
	
	ip_header->ip_sum = 0;
	ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
	

	/* populate ethernet header */
	
	ethernet_header->ether_type = htons(ethertype_ip);
	struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, routing_table_entry->gw.s_addr);
	struct sr_if* iface2 = sr_get_interface(sr, iface->name);
	
	      if (entry) { /* found entry */
	    	  
	    	  printf("Forwarding MAC address found. Forwarding packet.\n");
	    	  memcpy(ethernet_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
	    	  memcpy(ethernet_header->ether_shost, iface2->addr, ETHER_ADDR_LEN);
	    	  printf("ICMP packet attempting to send:\n\n");
	    	  print_hdrs(client_memory, sizeof(sr_ethernet_hdr_t)+ntohs(incoming_ip_hdr->ip_len));
	    	  int success = sr_send_packet(sr, client_memory, total_size, iface->name);
			  if (success!=0) {
				printf("ICMP reply failed to send.\n");
			  } else {
				printf("ICMP reply successfully sent.\n");
			  }
	      } else {
	    	  printf("No forwarding MAC entry found. Adding to queue.\n");
	    	  printf("ICMP packet adding to queue:\n\n");
	    	  print_hdrs(client_memory, total_size);
	    	  sr_arpcache_queuereq(&(sr->cache), routing_table_entry->gw.s_addr, client_memory, total_size, iface2->name); /*i'm assuming that sr_arpcache_sweepreqs handles everything */ 
	}
	/*free(icmp_header);*/
	return 0;
}





