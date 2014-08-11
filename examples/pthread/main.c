/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "main.h"
#include "pkt_buff.h"
#include <sys/time.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>

/* Key definitions */
#define NUM_QUEUE 2


#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define NB_MBUF  2048

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 4 /**< Default values of RX write-back threshold reg. */

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define TX_PTHRESH 36 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */

#define MAX_PKT_BURST 1
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

static unsigned int l2fwd_rx_queue_per_lcore = 1;

struct mbuf_table {
	unsigned len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct lcore_queue_conf {
	struct mbuf_table tx_mbufs[MAX_TX_QUEUE_PER_PORT];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[NUM_QUEUE];

static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = RX_PTHRESH,
		.hthresh = RX_HTHRESH,
		.wthresh = RX_WTHRESH,
	},
};

static const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = TX_PTHRESH,
		.hthresh = TX_HTHRESH,
		.wthresh = TX_WTHRESH,
	},
	.tx_free_thresh = 0, /* Use PMD default values */
	.tx_rs_thresh = 0, /* Use PMD default values */
	/*
	 * As the example won't handle mult-segments and offload cases,
	 * set the flag by default.
	 */
	.txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS,
};

struct rte_mempool * l2fwd_pktmbuf_pool[NUM_QUEUE];
struct rte_mempool * send_pktmbuf_pool;
#define NUM_MAX_CORE 32
/* Per-port statistics struct */
struct l2fwd_core_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
	int enable;
} __rte_cache_aligned;
struct l2fwd_core_statistics core_statistics[NUM_MAX_CORE];

/* A tsc-based timer responsible for triggering statistics printout */
#define TIMER_MILLISECOND 2000000ULL /* around 1ms at 2 Ghz */
#define MAX_TIMER_PERIOD 86400 /* 1 day max */
static int64_t timer_period = 10 * TIMER_MILLISECOND * 1000; /* default period is 10 seconds */

struct timeval startime;
struct timeval endtime;
int pktlen;
uint64_t ts_count[NUM_QUEUE], ts_total[NUM_QUEUE];

typedef struct context_s {
	unsigned int core_id;
	unsigned int queue_id;
} context_t;


void *rx_loop(context_t *);
void *tx_loop(context_t *);

/* Print out statistics on packets dropped */
	static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	uint64_t total_latency = 0, total_latency_cnt = 0;
	unsigned core_id, queue_id;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

	/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	struct timeval subtime;
	gettimeofday(&endtime, NULL);
	timersub(&endtime, &startime, &subtime);

	printf("\nPort statistics ====================================");

	for (core_id = 0; core_id < NUM_MAX_CORE; core_id ++) {
		if (core_statistics[core_id].enable == 0) continue;
		printf("\nStatistics for core %d ------------------------------"
				"    Packets sent: %11"PRIu64
				"    Packets received: %11"PRIu64
				"    Packets dropped: %11"PRIu64,
				core_id,
				core_statistics[core_id].tx,
				core_statistics[core_id].rx,
				core_statistics[core_id].dropped);

		total_packets_dropped += core_statistics[core_id].dropped;
		total_packets_tx += core_statistics[core_id].tx;
		total_packets_rx += core_statistics[core_id].rx;

		core_statistics[core_id].tx = 0;
		core_statistics[core_id].rx = 0;
		core_statistics[core_id].dropped = 0;
	}

	for (queue_id = 0; queue_id < NUM_QUEUE; queue_id ++) {
		total_latency += ts_total[queue_id];
		total_latency_cnt += ts_count[queue_id];
		ts_total[queue_id] = 0;
		ts_count[queue_id] = 1;
	}
	printf("\nAggregate statistics ==============================="
			"\nTotal packets sent: %18"PRIu64
			"\nTotal packets received: %14"PRIu64
			"\nTotal packets dropped: %15"PRIu64,
			total_packets_tx,
			total_packets_rx,
			total_packets_dropped);
	printf("\nTX Speed = %5.2lf Gbps, RX Speed = %5.2lf Gbps, latency count %18"PRIu64 " average %lf", 
			(double)(total_packets_tx * pktlen * 8) / (double) ((subtime.tv_sec*1000000+subtime.tv_usec) * 1000),
			(double)(total_packets_rx * pktlen * 8) / (double) ((subtime.tv_sec*1000000+subtime.tv_usec) * 1000),
			total_latency_cnt, (total_latency/total_latency_cnt)/(rte_get_tsc_hz()/1e6));
	printf("\n====================================================\n");
	
	gettimeofday(&startime, NULL);
}

/* main processing loop */
void *tx_loop(context_t *context)
{
	struct rte_mbuf *m;
	unsigned i;
	struct lcore_queue_conf *qconf;
	unsigned int core_id = context->core_id;
	unsigned int queue_id = context->queue_id;

	unsigned long mask = 1 << core_id;
	if (sched_setaffinity(0, sizeof(unsigned long), (cpu_set_t *)&mask) < 0) {
		assert(0);
	}

	qconf = &lcore_queue_conf[queue_id];

	RTE_LOG(INFO, L2FWD, "entering main loop on core %u\n", core_id);

	file_cache_t *fct;
	unsigned int tmp_pktlen;
	char *pktdata;
	if ((fct = preload_pcap_file(0)) != NULL) {
		printf("Loading done, core %d\n", core_id);
		if (!check_pcap(fct))
			printf("It is not trace file, core %d\n", core_id);
	} else {
		printf("Loading failed, core %d\n", core_id);
	}
	pktdata = (char *)prep_next_skb(fct, &tmp_pktlen);

	if (queue_id == 0) {
		pktlen = tmp_pktlen;
	}

	for (i = 0; i < MAX_PKT_BURST; i ++) {
		m = rte_pktmbuf_alloc(send_pktmbuf_pool);
		assert (m != NULL);
		m->pkt.nb_segs = 1;
		m->pkt.next = NULL;
		m->pkt.pkt_len = (uint16_t)pktlen;
		m->pkt.data_len = (uint16_t)pktlen;
		memcpy(m->pkt.data, pktdata, pktlen);
		qconf->tx_mbufs[queue_id].m_table[i] = m;
	}
	qconf->tx_mbufs[queue_id].len = MAX_PKT_BURST;


	struct rte_mbuf **m_table;
	uint32_t *ip;
	uint32_t ip_ctr = 1;
	unsigned int port, ret;
#if 0
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	prev_tsc = 0;
	timer_tsc = 0;
#endif

	if (queue_id == 0) {
		gettimeofday(&startime, NULL);
	}
	core_statistics[core_id].enable = 1;
	while (1) {
#if 0
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;

		/* if timer is enabled */
		if (timer_period > 0) {
			/* advance the timer */
			timer_tsc += diff_tsc;
			/* if timer has reached its timeout */
			if (unlikely(timer_tsc >= (uint64_t) timer_period)) {
				/* do this only on master core */
				if (queue_id == 0) {
					print_stats();
					/* reset the timer */
					timer_tsc = 0;
				}
			}
		}
		prev_tsc = cur_tsc;
#endif

		assert (qconf->tx_mbufs[queue_id].len == MAX_PKT_BURST);
		m_table = (struct rte_mbuf **)qconf->tx_mbufs[queue_id].m_table;
		for (i = 0; i < qconf->tx_mbufs[queue_id].len; i ++) {
			ip = (uint32_t *)((char *)(m_table[i]->pkt.data) + 26);
			*ip = ip_ctr ++;
			uint64_t now = rte_rdtsc_precise();
			*(uint64_t *)((char *)(m_table[i]->pkt.data) + 56) = now;
		}

		port = 0;
		ret = rte_eth_tx_burst(port, (uint16_t) queue_id, m_table, (uint16_t) qconf->tx_mbufs[queue_id].len);
		core_statistics[core_id].tx += ret;
		if (unlikely(ret < qconf->tx_mbufs[queue_id].len)) {
			core_statistics[core_id].dropped += (qconf->tx_mbufs[queue_id].len - ret);
		}
	}
}

/* main processing loop */
void *rx_loop(context_t *context)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	unsigned int core_id = context->core_id;
	unsigned int queue_id = context->queue_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	unsigned portid, nb_rx;

	unsigned long mask = 1 << core_id;
	if (sched_setaffinity(0, sizeof(unsigned long), (cpu_set_t *)&mask) < 0) {
		assert(0);
	}

	prev_tsc = 0;
	timer_tsc = 0;

	RTE_LOG(INFO, L2FWD, "entering main loop on core %u\n", core_id);
	core_statistics[core_id].enable = 1;

	while (1) {

		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;

		/* if timer is enabled */
		if (timer_period > 0) {
			/* advance the timer */
			timer_tsc += diff_tsc;
			/* if timer has reached its timeout */
			if (unlikely(timer_tsc >= (uint64_t) timer_period)) {
				/* do this only on master core */
				if (queue_id == 0) {
					print_stats();
					/* reset the timer */
					timer_tsc = 0;
				}
			}
		}
		prev_tsc = cur_tsc;

		/*
		 * Read packet from RX queues
		 */

		portid = 0; 
		nb_rx = rte_eth_rx_burst((uint8_t) portid, queue_id,
				pkts_burst, MAX_PKT_BURST);

		core_statistics[core_id].rx += nb_rx;

		if (nb_rx > 0) {
			m = pkts_burst[0];
			rte_prefetch0(rte_pktmbuf_mtod(m, void *));

			//uint64_t now = rte_rdtsc_precise();
			uint64_t now = rte_rdtsc();
			uint64_t ts = *(uint64_t *)((char *)(m->pkt.data) + 56);
			if (ts != 0) {
				ts_total[queue_id] += now - ts;
				ts_count[queue_id] ++;
			}
		}

		if (nb_rx > 0) {
			unsigned k = 0;
			do {
				rte_pktmbuf_free(pkts_burst[k]);
			} while (++k < nb_rx);
		}
	}
}

/* display usage */
static void
l2fwd_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
		   "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n",
	       prgname);
}

static unsigned int
l2fwd_parse_nqueue(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	if (n == 0)
		return 0;
	if (n >= MAX_RX_QUEUE_PER_LCORE)
		return 0;

	return n;
}

static int
l2fwd_parse_timer_period(const char *q_arg)
{
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n >= MAX_TIMER_PERIOD)
		return -1;

	return n;
}

/* Parse the argument given in the command line of the application */
static int
l2fwd_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "p:q:T:",
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* nqueue */
		case 'q':
			l2fwd_rx_queue_per_lcore = l2fwd_parse_nqueue(optarg);
			if (l2fwd_rx_queue_per_lcore == 0) {
				printf("invalid queue number\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* timer period */
		case 'T':
			timer_period = l2fwd_parse_timer_period(optarg) * 1000 * TIMER_MILLISECOND;
			if (timer_period < 0) {
				printf("invalid timer period\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* long options */
		case 0:
			l2fwd_usage(prgname);
			return -1;

		default:
			l2fwd_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 0; /* reset getopt lib */
	return ret;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

int
MAIN(int argc, char **argv)
{
	int ret;
	int i;
	uint8_t nb_ports;
	uint8_t portid, queue_id;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = l2fwd_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2FWD arguments\n");

	char str[10];
	/* create the mbuf pool */
	for(i = 0; i < NUM_QUEUE; i ++) {
		sprintf(str, "%d", i);
		l2fwd_pktmbuf_pool[i] =
			rte_mempool_create(str, NB_MBUF,
					MBUF_SIZE, 32,
					sizeof(struct rte_pktmbuf_pool_private),
					rte_pktmbuf_pool_init, NULL,
					rte_pktmbuf_init, NULL,
					rte_socket_id(), 0);
		if (l2fwd_pktmbuf_pool[i] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
	}

	send_pktmbuf_pool =
		rte_mempool_create("send_mbuf_pool", NB_MBUF,
				MBUF_SIZE, 32,
				sizeof(struct rte_pktmbuf_pool_private),
				rte_pktmbuf_pool_init, NULL,
				rte_pktmbuf_init, NULL,
				rte_socket_id(), 0);
	if (send_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	if (rte_eal_pci_probe() < 0)
		rte_exit(EXIT_FAILURE, "Cannot probe PCI\n");

	nb_ports = rte_eth_dev_count();
	assert (nb_ports == 1);

	/* Initialise each port */
	for (portid = 0; portid < nb_ports; portid++) {
		/* init port */
		printf("Initializing port %u... ", (unsigned) portid);
		ret = rte_eth_dev_configure(portid, NUM_QUEUE, NUM_QUEUE, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				  ret, (unsigned) portid);

		for (queue_id = 0; queue_id < NUM_QUEUE; queue_id ++) {
			/* init RX queues */
			ret = rte_eth_rx_queue_setup(portid, queue_id, nb_rxd,
					rte_eth_dev_socket_id(portid), &rx_conf,
					l2fwd_pktmbuf_pool[queue_id]);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
						ret, (unsigned) portid);

			/* init TX queues */
			ret = rte_eth_tx_queue_setup(portid, queue_id, nb_txd,
					rte_eth_dev_socket_id(portid), &tx_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
						ret, (unsigned) portid);
		}

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, (unsigned) portid);

		printf("done: \n");

		rte_eth_promiscuous_enable(portid);

		/* initialize port stats */
		memset(&core_statistics, 0, sizeof(core_statistics));
	}
	fflush(stdout);

	check_all_ports_link_status(nb_ports, 0);

	for (i = 0; i < NUM_QUEUE; i ++) {
		ts_total[i] = 0;
		ts_count[i] = 1;
	}

	pthread_t tid;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	context_t *context;

	for (i = 0; i < NUM_QUEUE; i ++) {
		
		context = (context_t *) malloc (sizeof(context_t));
		context->core_id = i * 2 + 1;
		context->queue_id = i;
		if (pthread_create(&tid, &attr, (void *)rx_loop, (void *)context) != 0) {
			perror("pthread_create error!!\n");
		}

		context = (context_t *) malloc (sizeof(context_t));
		context->core_id = (i + NUM_QUEUE) * 2 + 1;
		context->queue_id = i;
		if (pthread_create(&tid, &attr, (void *)tx_loop, (void *)context) != 0) {
			perror("pthread_create error!!\n");
		}
	}

	while (1) {
		sleep(10);
	}

	return 0;
}

