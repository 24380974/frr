/*
 * Copyright (c) 2015-19  David Lamparter, for NetDEF, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "zebra.h"

#include <sys/un.h>
#include <syslog.h>

#include "memory.h"
#include "frrcu.h"
#include "frr_pthread.h"
#include "printfrr.h"
#include "zlog.h"
#include "zlog_targets.h"

#include "lib/command.h"
#include "lib/version.h"

DEFINE_MTYPE_STATIC(LOG, LOG_5424,        "log 5424 target")
DEFINE_MTYPE_STATIC(LOG, LOG_5424_NAME,   "log 5424 name")
DEFINE_MTYPE_STATIC(LOG, LOG_5424_ROTATE, "log 5424 rotate helper")

struct zlt_5424 {
	struct zlog_target zt;

	atomic_uint_fast32_t fd;

	bool kw_version;
	bool kw_location;

	struct rcu_head_close head_close;
};

extern const char *zlog_progname;

static void zlog_5424(struct zlog_target *zt, struct zlog_msg *msgs[],
		      size_t nmsgs)
{
	struct zlt_5424 *zte = container_of(zt, struct zlt_5424, zt);
	int fd;
	size_t i, textlen, iovpos = 0;
	size_t niov = MIN(4 * nmsgs + 1, IOV_MAX);
	struct iovec iov[niov];
	/* "\n<n>1 YYYY-MM-DD HH:MM:SS.NNNNNNNNN+ZZ:ZZ " = 42 chars */
#define HDR_LEN 512
	char hdr_buf[HDR_LEN * nmsgs];
	struct fbuf hdr_pos = {
		.buf = hdr_buf,
		.pos = hdr_buf,
		.len = sizeof(hdr_buf),
	};

	fd = atomic_load_explicit(&zte->fd, memory_order_relaxed);

	for (i = 0; i < nmsgs; i++) {
		struct zlog_msg *msg = msgs[i];
		int prio = zlog_msg_prio(msg);
		const struct xref_logmsg *xref;
		struct xrefdata *xrefdata;

		if (prio > zt->prio_min)
			continue;

		iov[iovpos].iov_base = hdr_pos.pos;

		bprintfrr(&hdr_pos, "%s<%d>1 ", iovpos > 0 ? "\n" : "", prio);
		hdr_pos.pos += zlog_msg_ts(msg, hdr_pos.pos, hdr_pos.buf
					   + hdr_pos.len - hdr_pos.pos,
					   ZLOG_TS_ISO8601 | 6);
		bprintfrr(&hdr_pos, " %s %s %llu %.*s ",
			  cmd_hostname_get(), zlog_progname,
			  (long long)getpid(), (int)(zlog_prefixsz - 2),
			  zlog_prefix);

		/* XXX XXX XXX TODO: HDR_LEN is not appropriate; need to
		 * restructure the buffer management here
		 */
		if (zte->kw_version)
			bprintfrr(&hdr_pos, "[origin enterpriseId=\"50145\" software=\"FRRouting\" swVersion=\"%s\"]", FRR_VERSION);
		if (zte->kw_location
		    && (xref = zlog_msg_xref(msg))
		    && (xrefdata = xref->xref.xrefdata))
			bprintfrr(&hdr_pos, "[location@50145 id=\"%s\" file=\"%s\" line=\"%d\" func=\"%s\"]",
				  xrefdata->prefix, xref->xref.file, xref->xref.line, xref->xref.func);

		bprintfrr(&hdr_pos, " ");

		iov[iovpos].iov_len = hdr_pos.pos
			- (char *)iov[iovpos].iov_base;

		iovpos++;

		iov[iovpos].iov_base = (char *)zlog_msg_text(msg, &textlen);
		iov[iovpos].iov_len = textlen;

		iovpos++;

		if (hdr_pos.buf + hdr_pos.len - hdr_pos.pos < HDR_LEN
		    || i + 1 == nmsgs
		    || array_size(iov) - iovpos < 3) {
			iov[iovpos].iov_base = (char *)"\n";
			iov[iovpos].iov_len = 1;

			iovpos++;

			writev(fd, iov, iovpos);

			iovpos = 0;
			hdr_pos.pos = hdr_buf;
		}
	}

	assert(iovpos == 0);
}

/*
 * (re-)configuration
 */

struct zlog_cfg_5424 {
	struct zlt_5424 *active;

	pthread_mutex_t cfg_mtx;

	int prio_min;
	bool kw_version;
	bool kw_location;

	char *filename;
};

static void zlog_5424_init(struct zlog_cfg_5424 *zcf)
{
	memset(zcf, 0, sizeof(*zcf));
	zcf->prio_min = ZLOG_DISABLED;
	pthread_mutex_init(&zcf->cfg_mtx, NULL);
}

static void zlog_5424_target_free(struct zlt_5424 *zlt)
{
	if (!zlt)
		return;

	rcu_close(&zlt->head_close, zlt->fd);
	rcu_free(MTYPE_LOG_5424, zlt, zt.rcu_head);
}

static void zlog_5424_fini(struct zlog_cfg_5424 *zcf)
{
	if (zcf->active) {
		struct zlt_5424 *ztf;
		struct zlog_target *zt;

		zt = zlog_target_replace(&zcf->active->zt, NULL);
		ztf = container_of(zt, struct zlt_5424, zt);
		zlog_5424_target_free(ztf);
	}
	XFREE(MTYPE_LOG_5424_NAME, zcf->filename);
	pthread_mutex_destroy(&zcf->cfg_mtx);
}

static bool zlog_5424_cycle(struct zlog_cfg_5424 *zcf)
{
	struct zlog_target *zt, *old;
	struct zlt_5424 *zlt = NULL;
	int fd;
	bool rv = true;

	do {
		if (zcf->prio_min == ZLOG_DISABLED)
			break;

		fd = open("/tmp/zlog-5424",
				  O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC
					| O_NOCTTY,
				  LOGFILE_MASK);

		if (fd < 0) {
			rv = false;
			break;
		}

		zt = zlog_target_clone(MTYPE_LOG_5424, &zcf->active->zt,
				       sizeof(*zlt));
		zlt = container_of(zt, struct zlt_5424, zt);

		zlt->fd = fd;
		zlt->kw_version = zcf->kw_version;
		zlt->kw_location = zcf->kw_location;
		zlt->zt.prio_min = zcf->prio_min;
		zlt->zt.logfn = zlog_5424;
		zlt->zt.logfn_sigsafe = NULL; //zlog_fd_sigsafe;
	} while (0);

	old = zlog_target_replace(&zcf->active->zt, &zlt->zt);
	zcf->active = zlt;

	zlog_5424_target_free(container_of(old, struct zlt_5424, zt));

	return rv;
}

static void zlog_5424_set_other(struct zlog_cfg_5424 *zcf)
{
	frr_with_mutex(&zcf->cfg_mtx) {
		zlog_5424_cycle(zcf);
	}
}

#if 0
bool zlog_5424_set_filename(struct zlog_cfg_5424 *zcf, const char *filename)
{
	frr_with_mutex(&zcf->cfg_mtx) {
		XFREE(MTYPE_LOG_FD_NAME, zcf->filename);
		zcf->filename = XSTRDUP(MTYPE_LOG_FD_NAME, filename);
		zcf->fd = -1;

		return zlog_5424_cycle(zcf);
	}
	assert(0);
}

struct rcu_close_rotate {
	struct rcu_head_close head_close;
	struct rcu_head head_self;
};

bool zlog_5424_rotate(struct zlog_cfg_5424 *zcf)
{
	struct rcu_close_rotate *rcr;
	int fd;

	frr_with_mutex(&zcf->cfg_mtx) {
		if (!zcf->active || !zcf->filename)
			return true;

		fd = open(zcf->filename,
			  O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOCTTY,
			  LOGFILE_MASK);
		if (fd < 0)
			return false;

		fd = atomic_exchange_explicit(&zcf->active->fd,
					      (uint_fast32_t)fd,
					      memory_order_relaxed);
	}

	rcr = XCALLOC(MTYPE_LOG_FD_ROTATE, sizeof(*rcr));
	rcu_close(&rcr->head_close, fd);
	rcu_free(MTYPE_LOG_FD_ROTATE, rcr, head_self);

	return true;
}
#endif

/* CLI */

#ifndef VTYSH_EXTRACT_PL
#include "lib/zlog_5424_clippy.c"
#endif

static struct zlog_cfg_5424 cfg;

DEFPY (log_5424_target,
       log_5424_target_cmd,
       "log extended",
       "Logging control\n"
       "Extended RFC5424 syslog\n")
{
	zlog_5424_init(&cfg);

	cfg.kw_location = true;
	cfg.kw_version = false;
	cfg.prio_min = LOG_DEBUG;

	zlog_5424_set_other(&cfg);

	return CMD_SUCCESS;
}

DEFPY (no_log_5424_target,
       no_log_5424_target_cmd,
       "no log extended",
       NO_STR
       "Logging control\n"
       "Extended RFC5424 syslog\n")
{
	zlog_5424_fini(&cfg);
	return CMD_SUCCESS;
}


extern void log_5424_cmd_init(void);

void log_5424_cmd_init(void)
{
	install_element(CONFIG_NODE, &log_5424_target_cmd);
	install_element(CONFIG_NODE, &no_log_5424_target_cmd);
}
