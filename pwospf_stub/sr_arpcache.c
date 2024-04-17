#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_send_arp_request(struct sr_instance* sr, struct sr_arpreq* arp_request);
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
	printf("Sweeping requests...\n");
	    /* Get list of requests.*/
		struct sr_arpreq* current_requests = sr->cache.requests;
		/* Go through linked list of requests.*/
		while (current_requests != NULL) {
			printf("Checking request.\n");
			struct sr_arpreq* temp = current_requests->next;
			time_t current_time = time(NULL);
			if (difftime(current_time, current_requests->sent)>1.0) {
				if (current_requests->times_sent >= 5) {
					printf("Timing out. Sending ICMP exceptions.\n");
					struct sr_packet* packets = current_requests->packets;
					while (packets != NULL) {
						/* send icmp */
						packets = packets->next;
					}
					sr_arpreq_destroy(&(sr->cache), current_requests);
					current_requests = temp;
				} else {
					
					sr_send_arp_request(sr, current_requests);
					current_requests->sent = current_time;
					current_requests->times_sent++;
				}
			}
			current_requests = temp;
		}
}

void sr_send_arp_request(struct sr_instance* sr, struct sr_arpreq* arp_request) {
	printf("Need to resend ARP request.\n");
	/* Malloc space for request. */
	uint8_t* mem_block = malloc(sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t));
	/* Check for forwarding item in table */
	struct in_addr ip_check;
	
	ip_check.s_addr = arp_request->ip;
	printf("IP to send to: %d\n", arp_request->ip);
	
	struct sr_rt* routing_table_entry = search_rt(sr, ip_check);
	
	printf("Checking if entry\n");
	if (routing_table_entry == NULL) {
		printf("No entry found in table.");
		sr_arpreq_destroy(&sr->cache, arp_request);
		free(mem_block);
		return;
	} else {
		printf("Entry found:\n");
		sr_print_routing_entry(routing_table_entry);
	}
	
	struct sr_if* iface = sr_get_interface(sr, routing_table_entry->interface);
	
	/* Cast ARP and ethernet header. */
	sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(mem_block+sizeof(sr_ethernet_hdr_t));
	sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)mem_block;
	/* Add values to headers. */
	arp_header->ar_hln = 0x06;
	arp_header->ar_hrd = htons(arp_hrd_ethernet);
	arp_header->ar_pln = 0x04;
	arp_header->ar_pro = htons(ethertype_ip);
	arp_header->ar_op = htons(arp_op_request);
	/* Need source interface. */
	
	memcpy(arp_header->ar_sha, iface->addr, ETHER_ADDR_LEN);
	memset(arp_header->ar_tha, 0x00, ETHER_ADDR_LEN);
	arp_header->ar_sip = iface->ip;
	uint32_t next_hop_ip = 0;
	if (routing_table_entry->gw.s_addr ==0) {
		next_hop_ip = arp_request->ip;
	} else {
		next_hop_ip = routing_table_entry->gw.s_addr;
	}
	arp_header->ar_tip = next_hop_ip;

	memcpy(ethernet_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
	memset(ethernet_header->ether_dhost, 0xff, ETHER_ADDR_LEN);
	ethernet_header->ether_type = htons(ethertype_arp);
	/* Send the packet. */
	int success = sr_send_packet(sr, mem_block, sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t), iface->name);
	printf("SENDING ARP REQUEST\n\n\n");
	print_hdrs(mem_block, sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t));
	if (success != 0) {
		printf("Failed to send ARP request.");
	} else {
		printf("Sent ARP request.");
	}
	free(mem_block);
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

