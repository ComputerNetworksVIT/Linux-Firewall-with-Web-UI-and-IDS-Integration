
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

static int packet_handler(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                          struct nfq_data *nfa, void *data) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *packet_data;
    int payload_len;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    payload_len = nfq_get_payload(nfa, &packet_data);
    if (payload_len >= 0) {
        // Here you can inspect the packet data.
        // For example, you could parse the IP and TCP/UDP headers.
        struct iphdr *ip_header = (struct iphdr *)packet_data;

        // Example: Print source and destination IP addresses
        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = ip_header->saddr;
        dst_addr.s_addr = ip_header->daddr;

        printf("Received packet: ID %d, Src: %s, Dst: %s\n",
               id, inet_ntoa(src_addr), inet_ntoa(dst_addr));
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("Opening Netfilter library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "Error during nfq_open()\n");
        exit(1);
    }

    printf("Unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("Binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("Binding this program to queue '0'\n");
    qh = nfq_create_queue(h, 0, &packet_handler, NULL);
    if (!qh) {
        fprintf(stderr, "Error during nfq_create_queue()\n");
        exit(1);
    }

    printf("Setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    printf("Firewall core is running. Waiting for packets...\n");

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    printf("Unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    printf("Unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("Closing library handle\n");
    nfq_close(h);

    return 0;
}

