/*
 *
 *  hcimin -- minimal hcitool/hciconfig command
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2015       Benjamin Berg <benjamin@sipsolutions.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */


#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include "bluetooth.h"

#define APP_NAME "hcimin"

#ifndef SOURCE_VERSION
#define SOURCE_VERSION "2015.0.0"
#endif

#define MIN(a, b) ((a) < (b) ? (a) : (b))

/******************************************
 * Copy of functions/header data from hci.h other files that for needed
 * definitions.
 ******************************************/

#define HCI_MAX_DEV	16


struct hci_request {
	uint16_t ogf;
	uint16_t ocf;
	int      event;
	void     *cparam;
	int      clen;
	void     *rparam;
	int      rlen;
};

struct hci_version {
	uint16_t manufacturer;
	uint8_t  hci_ver;
	uint16_t hci_rev;
	uint8_t  lmp_ver;
	uint16_t lmp_subver;
};

/* LE address type */
enum {
	LE_PUBLIC_ADDRESS = 0x00,
	LE_RANDOM_ADDRESS = 0x01
};

/* HCI ioctl defines */
#define HCIDEVUP	_IOW('H', 201, int)
#define HCIDEVDOWN	_IOW('H', 202, int)
#define HCIDEVRESET	_IOW('H', 203, int)
#define HCIDEVRESTAT	_IOW('H', 204, int)

#define HCIGETDEVLIST	_IOR('H', 210, int)
#define HCIGETDEVINFO	_IOR('H', 211, int)
#define HCIGETCONNLIST	_IOR('H', 212, int)
#define HCIGETCONNINFO	_IOR('H', 213, int)
#define HCIGETAUTHINFO	_IOR('H', 215, int)

#define HCISETRAW	_IOW('H', 220, int)
#define HCISETSCAN	_IOW('H', 221, int)
#define HCISETAUTH	_IOW('H', 222, int)
#define HCISETENCRYPT	_IOW('H', 223, int)
#define HCISETPTYPE	_IOW('H', 224, int)
#define HCISETLINKPOL	_IOW('H', 225, int)
#define HCISETLINKMODE	_IOW('H', 226, int)
#define HCISETACLMTU	_IOW('H', 227, int)
#define HCISETSCOMTU	_IOW('H', 228, int)

#define HCIBLOCKADDR	_IOW('H', 230, int)
#define HCIUNBLOCKADDR	_IOW('H', 231, int)

#define HCIINQUIRY	_IOR('H', 240, int)


/* --------  HCI Packet structures  -------- */
#define HCI_TYPE_LEN	1

typedef struct {
	uint16_t	opcode;		/* OCF & OGF */
	uint8_t		plen;
} __attribute__ ((packed))	hci_command_hdr;
#define HCI_COMMAND_HDR_SIZE	3

typedef struct {
	uint8_t		evt;
	uint8_t		plen;
} __attribute__ ((packed))	hci_event_hdr;
#define HCI_EVENT_HDR_SIZE	2

typedef struct {
	uint16_t	handle;		/* Handle & Flags(PB, BC) */
	uint16_t	dlen;
} __attribute__ ((packed))	hci_acl_hdr;
#define HCI_ACL_HDR_SIZE	4

typedef struct {
	uint16_t	handle;
	uint8_t		dlen;
} __attribute__ ((packed))	hci_sco_hdr;
#define HCI_SCO_HDR_SIZE	3

typedef struct {
	uint16_t	device;
	uint16_t	type;
	uint16_t	plen;
} __attribute__ ((packed))	hci_msg_hdr;
#define HCI_MSG_HDR_SIZE	6

/* Command opcode pack/unpack */
#define cmd_opcode_pack(ogf, ocf)	(uint16_t)((ocf & 0x03ff)|(ogf << 10))
#define cmd_opcode_ogf(op)		(op >> 10)
#define cmd_opcode_ocf(op)		(op & 0x03ff)

/* ACL handle and flags pack/unpack */
#define acl_handle_pack(h, f)	(uint16_t)((h & 0x0fff)|(f << 12))
#define acl_handle(h)		(h & 0x0fff)
#define acl_flags(h)		(h >> 12)


#define HCI_MAX_EVENT_SIZE	260

struct sockaddr_hci {
	sa_family_t	hci_family;
	unsigned short	hci_dev;
	unsigned short  hci_channel;
};
#define HCI_DEV_NONE	0xffff

#define HCI_CHANNEL_RAW		0
#define HCI_CHANNEL_USER	1
#define HCI_CHANNEL_MONITOR	2
#define HCI_CHANNEL_CONTROL	3

/* HCI Packet types */
#define HCI_COMMAND_PKT		0x01
#define HCI_ACLDATA_PKT		0x02
#define HCI_SCODATA_PKT		0x03
#define HCI_EVENT_PKT		0x04
#define HCI_VENDOR_PKT		0xff

#define HCI_FLT_TYPE_BITS	31
#define HCI_FLT_EVENT_BITS	63
#define HCI_FLT_OGF_BITS	63
#define HCI_FLT_OCF_BITS	127

/* HCI Socket options */
#define HCI_DATA_DIR	1
#define HCI_FILTER	2
#define HCI_TIME_STAMP	3

/* Vendor specific commands */
#define OGF_VENDOR_CMD		0x3f
#define EVT_VENDOR			0xFF


#define HCI_MAX_NAME_LENGTH		248


/* Informational Parameters */
#define OGF_INFO_PARAM		0x04

/* LE commands */
#define OGF_LE_CTL		0x08

#define OCF_READ_LOCAL_VERSION		0x0001
typedef struct {
	uint8_t		status;
	uint8_t		hci_ver;
	uint16_t	hci_rev;
	uint8_t		lmp_ver;
	uint16_t	manufacturer;
	uint16_t	lmp_subver;
} __attribute__ ((packed)) read_local_version_rp;
#define READ_LOCAL_VERSION_RP_SIZE 9

#define OCF_LE_SET_SCAN_PARAMETERS		0x000B
typedef struct {
	uint8_t		type;
	uint16_t	interval;
	uint16_t	window;
	uint8_t		own_bdaddr_type;
	uint8_t		filter;
} __attribute__ ((packed)) le_set_scan_parameters_cp;
#define LE_SET_SCAN_PARAMETERS_CP_SIZE 7

#define OCF_LE_SET_SCAN_ENABLE			0x000C
typedef struct {
	uint8_t		enable;
	uint8_t		filter_dup;
} __attribute__ ((packed)) le_set_scan_enable_cp;
#define LE_SET_SCAN_ENABLE_CP_SIZE 2

#define EVT_CMD_COMPLETE		0x0E
typedef struct {
	uint8_t		ncmd;
	uint16_t	opcode;
} __attribute__ ((packed)) evt_cmd_complete;
#define EVT_CMD_COMPLETE_SIZE 3

#define EVT_CMD_STATUS			0x0F
typedef struct {
	uint8_t		status;
	uint8_t		ncmd;
	uint16_t	opcode;
} __attribute__ ((packed)) evt_cmd_status;
#define EVT_CMD_STATUS_SIZE 4

#define EVT_LE_ADVERTISING_REPORT	0x02
typedef struct {
	uint8_t		evt_type;
	uint8_t		bdaddr_type;
	bdaddr_t	bdaddr;
	uint8_t		length;
	uint8_t		data[0];
} __attribute__ ((packed)) le_advertising_info;
#define LE_ADVERTISING_INFO_SIZE 9

#define EVT_LE_META_EVENT	0x3E
typedef struct {
	uint8_t		subevent;
	uint8_t		data[0];
} __attribute__ ((packed)) evt_le_meta_event;
#define EVT_LE_META_EVENT_SIZE 1

#define EVT_REMOTE_NAME_REQ_COMPLETE	0x07
typedef struct {
	uint8_t		status;
	bdaddr_t	bdaddr;
	uint8_t		name[HCI_MAX_NAME_LENGTH];
} __attribute__ ((packed)) evt_remote_name_req_complete;
#define EVT_REMOTE_NAME_REQ_COMPLETE_SIZE 255

#define OCF_REMOTE_NAME_REQ		0x0019
typedef struct {
	bdaddr_t	bdaddr;
	uint8_t		pscan_rep_mode;
	uint8_t		pscan_mode;
	uint16_t	clock_offset;
} __attribute__ ((packed)) remote_name_req_cp;
#define REMOTE_NAME_REQ_CP_SIZE 10

/* Ioctl requests structures */
struct hci_dev_stats {
	uint32_t err_rx;
	uint32_t err_tx;
	uint32_t cmd_tx;
	uint32_t evt_rx;
	uint32_t acl_tx;
	uint32_t acl_rx;
	uint32_t sco_tx;
	uint32_t sco_rx;
	uint32_t byte_rx;
	uint32_t byte_tx;
};


struct hci_dev_info {
	uint16_t dev_id;
	char     name[8];

	bdaddr_t bdaddr;

	uint32_t flags;
	uint8_t  type;

	uint8_t  features[8];

	uint32_t pkt_type;
	uint32_t link_policy;
	uint32_t link_mode;

	uint16_t acl_mtu;
	uint16_t acl_pkts;
	uint16_t sco_mtu;
	uint16_t sco_pkts;

	struct   hci_dev_stats stat;
};

struct hci_dev_req {
	uint16_t dev_id;
	uint32_t dev_opt;
};

struct hci_dev_list_req {
	uint16_t dev_num;
	struct hci_dev_req dev_req[0];	/* hci_dev_req structures */
};



static inline void hci_set_bit(int nr, void *addr)
{
	*((uint32_t *) addr + (nr >> 5)) |= (1 << (nr & 31));
}

static inline void hci_clear_bit(int nr, void *addr)
{
	*((uint32_t *) addr + (nr >> 5)) &= ~(1 << (nr & 31));
}

static inline int hci_test_bit(int nr, void *addr)
{
	return *((uint32_t *) addr + (nr >> 5)) & (1 << (nr & 31));
}



struct hci_filter {
	uint32_t type_mask;
	uint32_t event_mask[2];
	uint16_t opcode;
};


/* HCI filter tools */
static inline void hci_filter_clear(struct hci_filter *f)
{
	memset(f, 0, sizeof(*f));
}
static inline void hci_filter_set_ptype(int t, struct hci_filter *f)
{
	hci_set_bit((t == HCI_VENDOR_PKT) ? 0 : (t & HCI_FLT_TYPE_BITS), &f->type_mask);
}
static inline void hci_filter_clear_ptype(int t, struct hci_filter *f)
{
	hci_clear_bit((t == HCI_VENDOR_PKT) ? 0 : (t & HCI_FLT_TYPE_BITS), &f->type_mask);
}
static inline int hci_filter_test_ptype(int t, struct hci_filter *f)
{
	return hci_test_bit((t == HCI_VENDOR_PKT) ? 0 : (t & HCI_FLT_TYPE_BITS), &f->type_mask);
}
static inline void hci_filter_all_ptypes(struct hci_filter *f)
{
	memset((void *) &f->type_mask, 0xff, sizeof(f->type_mask));
}
static inline void hci_filter_set_event(int e, struct hci_filter *f)
{
	hci_set_bit((e & HCI_FLT_EVENT_BITS), &f->event_mask);
}
static inline void hci_filter_clear_event(int e, struct hci_filter *f)
{
	hci_clear_bit((e & HCI_FLT_EVENT_BITS), &f->event_mask);
}
static inline int hci_filter_test_event(int e, struct hci_filter *f)
{
	return hci_test_bit((e & HCI_FLT_EVENT_BITS), &f->event_mask);
}
static inline void hci_filter_all_events(struct hci_filter *f)
{
	memset((void *) f->event_mask, 0xff, sizeof(f->event_mask));
}
static inline void hci_filter_set_opcode(int opcode, struct hci_filter *f)
{
	f->opcode = opcode;
}
static inline void hci_filter_clear_opcode(struct hci_filter *f)
{
	f->opcode = 0;
}
static inline int hci_filter_test_opcode(int opcode, struct hci_filter *f)
{
	return (f->opcode == opcode);
}

/* Open HCI device.
 * Returns device descriptor (dd). */
static int hci_open_dev(int dev_id)
{
	struct sockaddr_hci a;
	int dd, err;

	/* Create HCI socket */
	dd = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
	if (dd < 0)
		return dd;

	/* Bind socket to the HCI device */
	if (dev_id > 0) {
		memset(&a, 0, sizeof(a));
		a.hci_family = AF_BLUETOOTH;
		a.hci_dev = dev_id;
		if (bind(dd, (struct sockaddr *) &a, sizeof(a)) < 0)
			goto failed;
	}

	return dd;

failed:
	err = errno;
	close(dd);  
	errno = err;

	return -1;
}


/* HCI functions that require open device
 * dd - Device descriptor returned by hci_open_dev. */

static int hci_send_cmd(int dd, uint16_t ogf, uint16_t ocf, uint8_t plen, void *param)
{
	uint8_t type = HCI_COMMAND_PKT;
	hci_command_hdr hc;
	struct iovec iv[3];
	int ivn;

	hc.opcode = htobs(cmd_opcode_pack(ogf, ocf));
	hc.plen= plen;

	iv[0].iov_base = &type;
	iv[0].iov_len  = 1;  
	iv[1].iov_base = &hc;
	iv[1].iov_len  = HCI_COMMAND_HDR_SIZE;
	ivn = 2;

	if (plen) {
		iv[2].iov_base = param;
		iv[2].iov_len  = plen;
		ivn = 3;
	}

	while (writev(dd, iv, ivn) < 0) {
		if (errno == EAGAIN || errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

int hci_send_req(int dd, struct hci_request *r, int to)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
	uint16_t opcode = htobs(cmd_opcode_pack(r->ogf, r->ocf));
	struct hci_filter nf, of;
	socklen_t olen;
	hci_event_hdr *hdr;
	int err, try;

	olen = sizeof(of);
	if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0)
		return -1;

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT,  &nf);
	hci_filter_set_event(EVT_CMD_STATUS, &nf);
	hci_filter_set_event(EVT_CMD_COMPLETE, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);
	hci_filter_set_event(r->event, &nf);
	hci_filter_set_opcode(opcode, &nf);
	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0)
		return -1;

	if (hci_send_cmd(dd, r->ogf, r->ocf, r->clen, r->cparam) < 0)
		goto failed;

	try = 10;
	while (try--) {
		evt_cmd_complete *cc;
		evt_cmd_status *cs;
		evt_remote_name_req_complete *rn;
		evt_le_meta_event *me;
		remote_name_req_cp *cp;
		int len;

		if (to) {
			struct pollfd p;
			int n;

			p.fd = dd; p.events = POLLIN;
			while ((n = poll(&p, 1, to)) < 0) {
				if (errno == EAGAIN || errno == EINTR)
					continue;
				goto failed;
			}

			if (!n) {
				errno = ETIMEDOUT;
				goto failed;
			}

			to -= 10;
			if (to < 0)
				to = 0;

		}

		while ((len = read(dd, buf, sizeof(buf))) < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			goto failed;
		}

		hdr = (void *) (buf + 1);
		ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
		len -= (1 + HCI_EVENT_HDR_SIZE);

		switch (hdr->evt) {
		case EVT_CMD_STATUS:
			cs = (void *) ptr;

			if (cs->opcode != opcode)
				continue;

			if (r->event != EVT_CMD_STATUS) {
				if (cs->status) {
					errno = EIO;
					goto failed;
				}
				break;
			}

			r->rlen = MIN(len, r->rlen);
			memcpy(r->rparam, ptr, r->rlen);
			goto done;

		case EVT_CMD_COMPLETE:
			cc = (void *) ptr;

			if (cc->opcode != opcode)
				continue;

			ptr += EVT_CMD_COMPLETE_SIZE;
			len -= EVT_CMD_COMPLETE_SIZE;

			r->rlen = MIN(len, r->rlen);
			memcpy(r->rparam, ptr, r->rlen);
			goto done;

		case EVT_REMOTE_NAME_REQ_COMPLETE:
			if (hdr->evt != r->event)
				break;

			rn = (void *) ptr;
			cp = r->cparam;

			if (bacmp(&rn->bdaddr, &cp->bdaddr))
				continue;

			r->rlen = MIN(len, r->rlen);
			memcpy(r->rparam, ptr, r->rlen);
			goto done;

		case EVT_LE_META_EVENT:
			me = (void *) ptr;

			if (me->subevent != r->event)
				continue;

			len -= 1;
			r->rlen = MIN(len, r->rlen);
			memcpy(r->rparam, me->data, r->rlen);
			goto done;

		default:
			if (hdr->evt != r->event)
				break;

			r->rlen = MIN(len, r->rlen);
			memcpy(r->rparam, ptr, r->rlen);
			goto done;
		}
	}
	errno = ETIMEDOUT;

failed:
	err = errno;
	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
	errno = err;
	return -1;

done:
	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
	return 0;
}

int hci_read_local_version(int dd, struct hci_version *ver, int to)
{
	read_local_version_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_INFO_PARAM;
	rq.ocf    = OCF_READ_LOCAL_VERSION;
	rq.rparam = &rp;
	rq.rlen   = READ_LOCAL_VERSION_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	ver->manufacturer = btohs(rp.manufacturer);
	ver->hci_ver      = rp.hci_ver;
	ver->hci_rev      = btohs(rp.hci_rev);
	ver->lmp_ver      = rp.lmp_ver;
	ver->lmp_subver   = btohs(rp.lmp_subver);
	return 0;
}

int hci_le_set_scan_enable(int dd, uint8_t enable, uint8_t filter_dup, int to)
{
	struct hci_request rq;
	le_set_scan_enable_cp scan_cp;
	uint8_t status;

	memset(&scan_cp, 0, sizeof(scan_cp));
	scan_cp.enable = enable;
	scan_cp.filter_dup = filter_dup;

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_SET_SCAN_ENABLE;
	rq.cparam = &scan_cp;
	rq.clen = LE_SET_SCAN_ENABLE_CP_SIZE;
	rq.rparam = &status;
	rq.rlen = 1;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_le_set_scan_parameters(int dd, uint8_t type,
					uint16_t interval, uint16_t window,
					uint8_t own_type, uint8_t filter, int to)
{
	struct hci_request rq;
	le_set_scan_parameters_cp param_cp;
	uint8_t status;

	memset(&param_cp, 0, sizeof(param_cp));
	param_cp.type = type;
	param_cp.interval = interval;
	param_cp.window = window;
	param_cp.own_bdaddr_type = own_type;
	param_cp.filter = filter;

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = OCF_LE_SET_SCAN_PARAMETERS;
	rq.cparam = &param_cp;
	rq.clen = LE_SET_SCAN_PARAMETERS_CP_SIZE;
	rq.rparam = &status;
	rq.rlen = 1;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (status) {
		errno = EIO;
		return -1;
	}

	return 0;
}



/******************************************
 * End of copied data
 ******************************************/

/* The following functions are from bluetooth.c. */

static int bachk(const char *str)
{
	if (!str)
		return -1;

	if (strlen(str) != 17)
		return -1;

	while (*str) {
		if (!isxdigit(*str++))
			return -1;

		if (!isxdigit(*str++))
			return -1;

		if (*str == 0)
			break;

		if (*str++ != ':')
			return -1;
	}

	return 0;
}

static int ba2str(const bdaddr_t *ba, char *str)
{
	return sprintf(str, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
		ba->b[5], ba->b[4], ba->b[3], ba->b[2], ba->b[1], ba->b[0]);
}

static int str2ba(const char *str, bdaddr_t *ba)
{
	int i;

	if (bachk(str) < 0) {
		memset(ba, 0, sizeof(*ba));
		return -1;
	}

	for (i = 5; i >= 0; i--, str += 3)
		ba->b[i] = strtol(str, NULL, 16);

	return 0;
}

static void hex_dump(char *pref, int width, unsigned char *buf, int len)
{
	register int i,n;

	for (i = 0, n = 1; i < len; i++, n++) {
		if (n == 1)
			printf("%s", pref);
		printf("%2.2X ", buf[i]);
		if (n == width) {
			printf("\n");
			n = 0;
		}
	}
	if (i && n!=1)
		printf("\n");
}


#include "bdaddr-stripped.c"


/** */

static int cmd_list(int ctl, int hdev, int argc, char *argv[])
{
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	int i;

	if (!(dl = malloc(HCI_MAX_DEV * sizeof(struct hci_dev_req) +
		sizeof(uint16_t)))) {
		perror("Can't allocate memory");
		return 1;
	}
	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(ctl, HCIGETDEVLIST, (void *) dl) < 0) {
		perror("Can't get device list");
		return 1;
	}

	for (i = 0; i< dl->dev_num; i++) {
		printf("hci%i\n", (dr+i)->dev_id);
	}
	return 0;
}

static int cmd_info(int ctl, int hdev, int argc, char *argv[])
{
	struct hci_dev_info di;
	struct hci_dev_stats *st = &di.stat;

	di.dev_id = hdev;
	if (ioctl(ctl, HCIGETDEVINFO, (void *) &di)) {
		perror("Can't get device info");
		return 1;
	}

	char addr[18];

	ba2str(&di.bdaddr, addr);

	printf("%s:\tType: %x  Bus: %x\n", di.name,
					(di.type & 0x30) >> 4,
					di.type & 0x0f);
	printf("\tBD Address: %s  ACL MTU: %d:%d  SCO MTU: %d:%d\n",
					addr, di.acl_mtu, di.acl_pkts,
						di.sco_mtu, di.sco_pkts);


	printf("\tFlags: 0x%08X\n", di.flags);

	printf("\tRX bytes:%d acl:%d sco:%d events:%d errors:%d\n",
		st->byte_rx, st->acl_rx, st->sco_rx, st->evt_rx, st->err_rx);

	printf("\tTX bytes:%d acl:%d sco:%d commands:%d errors:%d\n",
		st->byte_tx, st->acl_tx, st->sco_tx, st->cmd_tx, st->err_tx);

	printf("\n");

	return 0;
}

static int cmd_cmd(int ctl, int hdev, int argc, char *argv[])
{
	struct hci_filter flt;
	int i;
	int ogf, ocf;
	int buf_len = 0;
	int len;
	uint8_t buf[HCI_MAX_EVENT_SIZE], *ptr;
	hci_event_hdr *hdr;

	if (argc < 2) {
		printf("Not enough arguments.\n");
		return 1;
	}

	ogf = strtol(argv[0], NULL, 16);
	ocf = strtol(argv[1], NULL, 16);

	for (i = 2; argv[i] && buf_len < HCI_MAX_EVENT_SIZE; i++) {
		buf[buf_len] = (int8_t) strtol(argv[i], NULL, 16);
		buf_len++;
	}

	hci_filter_clear(&flt);
	hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
	hci_filter_all_events(&flt);
	if (setsockopt(ctl, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
		perror("HCI filter setup failed");
		exit(EXIT_FAILURE);
	}

	if (hci_send_cmd(ctl, ogf, ocf, buf_len, buf) < 0) {
		perror("Send failed");
		exit(EXIT_FAILURE);   
	}

	len = read(ctl, buf, sizeof(buf));
	if (len < 0) {
		perror("Read failed");
		exit(EXIT_FAILURE);   
	}

	hdr = (void *)(buf + 1);
	ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
	len -= (1 + HCI_EVENT_HDR_SIZE);

	printf("> HCI Event: 0x%02x plen %d\n", hdr->evt, hdr->plen);
	hex_dump("  ", 20, ptr, len);

	return 0;
}


static int cmd_up(int ctl, int hdev, int argc, char *argv[])
{
	if (ioctl(ctl, HCIDEVUP, hdev) < 0) {
		if (errno == EALREADY)
			return 0;
		printf("Can't init device hci%d: %d\n",
		       hdev, errno);
		return 1;
	}
	return 0;
}

static int cmd_down(int ctl, int hdev, int argc, char *argv[])
{
	if (ioctl(ctl, HCIDEVDOWN, hdev) < 0) {
		printf("Can't deinit device hci%d: %d\n",
		       hdev, errno);
		return 1;
	}
	return 0;
}

static int cmd_reset(int ctl, int hdev, int argc, char *argv[])
{
	if (ioctl(ctl, HCIDEVRESET, hdev) < 0) {
		printf("Can't reset device hci%d: %d\n",
		       hdev, errno);
		return 1;
	}
	return 0;
}

static int cmd_vreset(int ctl, int hdev, int argc, char *argv[])
{
	int i;
	struct hci_version ver;

	/* XXX: The original bdaddr code also reads the device info, this
	 *      does not seem to be neccessary. */
	if (hci_read_local_version(ctl, &ver, 1000) < 0) {
		fprintf(stderr, "Can't read version info for hci%d: %d\n",
			hdev, errno);
		return 1;
	}

	for (i = 0; vendor[i].compid != 65535; i++)  {
		if (ver.manufacturer == vendor[i].compid) {

			if (vendor[i].reset_device(ctl) < 0) {
				if (errno != 32) {
					printf("Could not reset device, reset manally!\n");
				} else {
					printf("Reset probably worked (broken pipe).\n");
				}
			} else {
				ioctl(ctl, HCIDEVRESET, hdev);
				printf("Device reset successfully!\n");
			}

			return 0;
		}
	}

	fprintf(stderr, "Vendor not supported!\n");
	return 1;
}

/**
 * cmd_addr() - 
 * @argc:	Argument count for the process.
 * @argv:	Argument array for the process.
 */
static int cmd_addr(int ctl, int hdev, int argc, char *argv[])
{
	int i;
	bdaddr_t new_addr;
	struct hci_version ver;

	if (argc != 1) {
		printf("Wrong number of parameters. Need new addr.\n");
		return 1;
	}

	str2ba(argv[0], &new_addr);

	/* XXX: The original bdaddr code also reads the device info, this
	 *      does not seem to be neccessary. */
	if (hci_read_local_version(ctl, &ver, 1000) < 0) {
		fprintf(stderr, "Can't read version info for hci%d: %d\n",
			hdev, errno);
		return 1;
	}

	for (i = 0; vendor[i].compid != 65535; i++)  {
		if (ver.manufacturer == vendor[i].compid) {

			if (vendor[i].write_bd_addr(ctl, &new_addr) < 0) {
				fprintf(stderr, "Can't write new address\n");
				return 1;
			}

			printf("Address changed - ");

			if (vendor[i].reset_device(ctl) < 0) {
				if (errno != 32) {
					printf("Could not reset device, reset manally!\n");
				} else {
					printf("Reset probably worked (broken pipe).\n");
				}
			} else {
				if (ioctl(ctl, HCIDEVRESET, hdev) < 0) {
					printf("Error sending HCI reset ioctl\n");
				} else {
					printf("Device reset successfully\n");
				}
			}

			return 0;
		}
	}

	fprintf(stderr, "Vendor not supported!\n");
	return 1;
}


static volatile int signal_received = 0;

static void sigint_handler(int sig)
{
	signal_received = sig;
}

const uint8_t ibeacon_prefix[9] = {0x02, 0x01, 0x06, 0x1A, 0xFF, 0x4C, 0x00, 0x02, 0x15};

static int print_advertising_devices(int ctl)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
	struct hci_filter nf, of;
	struct sigaction sa;
	socklen_t olen;
	int len;

	olen = sizeof(of);
	if (getsockopt(ctl, SOL_HCI, HCI_FILTER, &of, &olen) < 0) {
		printf("Could not get socket options\n");
		return -1;
	}

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);

	if (setsockopt(ctl, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
		printf("Could not set socket options\n");
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sigint_handler;
	sigaction(SIGINT, &sa, NULL);

	while (1) {
		evt_le_meta_event *meta;
		le_advertising_info *info;

		while ((len = read(ctl, buf, sizeof(buf))) < 0) {
			if (errno == EINTR && signal_received == SIGINT) {
				len = 0;
				goto done;
			}

			if (errno == EAGAIN || errno == EINTR)
				continue;
			goto done;
		}

		ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
		len -= (1 + HCI_EVENT_HDR_SIZE);

		meta = (void *) ptr;

		if (meta->subevent != 0x02)
			goto done;

		info = (le_advertising_info *) (meta->data + 1);

		printf("got subevent 0x02 with length %i, payload %i\n", len, info->length);

		if (info->length == 0x1e && memcmp(info->data, ibeacon_prefix, sizeof(ibeacon_prefix))) {
			printf("got ibeacon:\n");

			printf("  uuid: %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
			info->data[9], info->data[10], info->data[11], info->data[12],
			info->data[13], info->data[14], info->data[15], info->data[16],
			info->data[17], info->data[18], info->data[19], info->data[20],
			info->data[21], info->data[22], info->data[23], info->data[24]);

			/* major/minor is given as big endian values. */
			printf("  major: %d\n", info->data[25] << 8 | info->data[26]);
			printf("  minor: %d\n", info->data[27] << 8 | info->data[28]);
			printf("  tx power: %x\n", info->data[29]);
			printf("  rx power: %x\n", info->data[30]);
			printf("  bdaddr: %02x:%02x:%02x:%02x:%02x:%02x\n",
				info->bdaddr.b[5], info->bdaddr.b[4], info->bdaddr.b[3],
				info->bdaddr.b[2], info->bdaddr.b[1], info->bdaddr.b[0]);

		}

		/* Only print found iBeacons (ignore everything else). */

	}

done:
	setsockopt(ctl, SOL_HCI, HCI_FILTER, &of, sizeof(of));

	if (len < 0)
		return -1;

	return 0;
}

static int cmd_scan(int ctl, int hdev, int argc, char *argv[])
{
	/* We need to:
	 *  * enable passive scanning
	 *  * handle interrupts (uh, right?)
	 *  * change filters
	 *
	 *
	 **/
	uint16_t interval = htobs(0x0010);
	uint16_t window = htobs(0x0010);
	uint8_t own_type = LE_PUBLIC_ADDRESS;
	uint8_t scan_type = 0x00; /* passive */
	uint8_t filter_dup = 0x00; /* do not filter duplicates */
	uint8_t filter_policy = 0x00;
	int err;

	err = hci_le_set_scan_parameters(ctl, scan_type, interval, window,
						own_type, filter_policy, 10000);
	if (err < 0) {
		perror("Set scan parameters failed");
		return 1;
	}

	err = hci_le_set_scan_enable(ctl, 0x01, filter_dup, 10000);
	if (err < 0) {
		perror("Enable scan failed");
		return 1;
	}

	printf("LE Scan ...\n");

	err = print_advertising_devices(ctl);
	if (err < 0) {
		perror("Could not receive advertising events");
		return 1;
	}

	err = hci_le_set_scan_enable(ctl, 0x00, filter_dup, 10000);
	if (err < 0) {
		perror("Disable scan failed");
		return 1;
	}

	return 0;
}


static struct {
	char *cmd;
	int reqdev;
	int (*func)(int ctl, int hdev, int argc, char *argv[]);
	char *opt;
	char *doc;
} commands[] = {
	{ "list", 0, cmd_list, NULL, "Show HCI device information" },
	{ "info", 1, cmd_info, NULL, "Show HCI device information" },
	{ "reset", 1, cmd_reset, NULL, "Reset HCI device" },
	{ "vreset", 1, cmd_vreset, NULL, "Reset HCI device using vendor specific commands" },
	{ "up", 1, cmd_up, NULL, "Open and initialize HCI device" },
	{ "down", 1, cmd_down, NULL, "Close HCI device" },
	{ "addr", 1, cmd_addr, "<bdaddr>", "Try setting devices MAC address (device dependent)" },
	{ "cmd", 1, cmd_cmd, "<ogf> <ocf> [parameters]", "Send command to HCI device (params are hex)" },
	{ "scan", 1, cmd_scan, NULL, "Passively scan for bluetooth beacons in the vincinity" },
	{ NULL, 0, NULL, NULL, NULL },
};


/**
 * usage() - Print usage information to stdout.
 * @argc:	Argument count for the process.
 * @argv:	Argument array for the process.
 */
static void usage(int argc, char *argv[])
{
	const char *app = APP_NAME;
	int cmd;

	if (argc > 1)
		app = argv[0];

	printf(APP_NAME " v" SOURCE_VERSION "\n");
	printf("Usage: %s (hciX command|list)\n\n", app);
	printf("with command being one of:\n");

	for (cmd = 0; commands[cmd].cmd != NULL; cmd++) {
		printf("\t %-5s %-15s\t%s\n",
			commands[cmd].cmd,
			commands[cmd].opt ? commands[cmd].opt : "",
			commands[cmd].doc);
	}
}


/**
 * main() - Main program function.
 * @argc:	Argument count for the process.
 * @argv:	Argument array for the process.
 */
int main(int argc, char *argv[])
{
	int ret;
	int cmd;
	int hdev;
	int ctl;
	int strip;

	/* Do not flash the info, that way it doesn't hurt to reset it all the time. */
	transient = 1;

	if (argc < 2) {
		usage(argc, argv);
		return 1;
	}

	for (cmd = 0; commands[cmd].cmd; cmd++) {
		if (strcmp(argv[1], commands[cmd].cmd) == 0)
			break;
	}

	if (commands[cmd].cmd == NULL) {
		usage(argc, argv);
		return 1;
	}

	if (commands[cmd].reqdev) {
		strip = 3;

		if (strlen(argv[2]) < 4 || strncmp("hci", argv[2], 3) != 0) {
			printf("Not a valid HCI device.\n");
			return 1;
		}

		hdev = atol(argv[2] + 3);
	} else {
		strip = 2;
		hdev = -1;
	}

	/* Have a command, open up device now. */
	ctl = hci_open_dev(hdev);
	if (ctl < 0) {
		printf("Could not open control socket or HCI device.\n");
		return 1;
	}

	/* Device is open, and we have command to handle everything, call into
	 * the command now.*/
	ret = commands[cmd].func(ctl, hdev, argc - strip, argv + strip);

	close(ctl);

	return ret;
}


