/*
 * FRR filter CLI implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include "zebra.h"

#include "lib/command.h"
#include "lib/filter.h"
#include "lib/northbound_cli.h"

#ifndef VTYSH_EXTRACT_PL
#include "lib/filter_cli_clippy.c"
#endif /* VTYSH_EXTRACT_PL */

#define ACCESS_LIST_STR "Access list entry\n"
#define ACCESS_LIST_LEG_STR "IP standard access list\n"
#define ACCESS_LIST_LEG_EXT_STR "IP standard access list (expanded range)\n"
#define ACCESS_LIST_ELEG_STR "IP extended access list\n"
#define ACCESS_LIST_ELEG_EXT_STR "IP extended access list (expanded range)\n"
#define ACCESS_LIST_XLEG_STR                                                   \
	ACCESS_LIST_LEG_STR                                                    \
	ACCESS_LIST_LEG_EXT_STR                                                \
	ACCESS_LIST_ELEG_STR                                                   \
	ACCESS_LIST_ELEG_EXT_STR
#define ACCESS_LIST_ZEBRA_STR "Access list entry\n"
#define ACCESS_LIST_SEQ_STR                                                    \
	"Sequence number of an entry\n"                                        \
	"Sequence number\n"
#define ACCESS_LIST_ACTION_STR                                                 \
	"Specify packets to reject\n"                                          \
	"Specify packets to forward\n"
#define ACCESS_LIST_REMARK_STR "Access list entry comment\n"
#define ACCESS_LIST_REMARK_LINE_STR "Comment up to 100 characters\n"

/*
 * Helper function to locate filter data structures for Cisco-style ACLs.
 */
static int64_t acl_cisco_get_seq(struct access_list *acl, const char *action,
				 const char *src, const char *src_mask,
				 const char *dst, const char *dst_mask)
{
	struct filter_cisco *fc;
	struct filter f, *fn;

	memset(&f, 0, sizeof(f));
	memset(&fc, 0, sizeof(fc));
	f.cisco = 1;
	if (strcmp(action, "permit") == 0)
		f.type = FILTER_PERMIT;
	else
		f.type = FILTER_DENY;

	fc = &f.u.cfilter;
	inet_pton(AF_INET, src, &fc->addr);
	inet_pton(AF_INET, src_mask, &fc->addr_mask);
	fc->addr.s_addr &= ~fc->addr_mask.s_addr;
	if (dst != NULL) {
		fc->extended = 1;
		inet_pton(AF_INET, dst, &fc->mask);
		inet_pton(AF_INET, dst_mask, &fc->mask_mask);
		fc->mask.s_addr &= ~fc->mask_mask.s_addr;
	}

	fn = filter_lookup_cisco(acl, &f);
	if (fn == NULL)
		return -1;

	return fn->seq;
}

/*
 * Helper function to locate filter data structures for zebra-style ACLs.
 */
static int64_t acl_zebra_get_seq(struct access_list *acl, const char *action,
				 const struct prefix *p, bool exact)
{
	struct filter_zebra *fz;
	struct filter f, *fn;

	memset(&f, 0, sizeof(f));
	memset(&fz, 0, sizeof(fz));
	if (strcmp(action, "permit") == 0)
		f.type = FILTER_PERMIT;
	else
		f.type = FILTER_DENY;

	fz = &f.u.zfilter;
	fz->prefix = *p;
	fz->exact = exact;

	fn = filter_lookup_zebra(acl, &f);
	if (fn == NULL)
		return -1;

	return fn->seq;
}

/*
 * Helper function to concatenate address with mask in Cisco style.
 */
static void concat_addr_mask_v4(const char *addr, const char *mask, char *dst,
				size_t dstlen)
{
	struct in_addr ia;
	int plen;

	assert(inet_pton(AF_INET, mask, &ia) == 1);
	plen = ip_masklen(ia);
	snprintf(dst, dstlen, "%s/%d", addr, plen);
}

/*
 * Cisco (legacy) access lists.
 */
DEFPY(
	access_list_std, access_list_std_cmd,
	"access-list <(1-99)|(1300-1999)>$number [seq (1-4294967295)$seq] <deny|permit>$action <[host] A.B.C.D$host|A.B.C.D$host A.B.C.D$mask|any>",
	ACCESS_LIST_STR
	ACCESS_LIST_LEG_STR
	ACCESS_LIST_LEG_EXT_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"A single host address\n"
	"Address to match\n"
	"Address to match\n"
	"Wildcard bits\n"
	"Any source host\n")
{
	struct access_list *acl;
	struct lyd_node *dnode;
	int rv;
	int64_t sseq;
	char ipmask[64];
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 32];
	char xpath_value[XPATH_MAXLEN + 64];

	/*
	 * Create the access-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list-legacy[number='%s']", number_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	rv = nb_cli_apply_changes(vty, NULL);
	if (rv != CMD_SUCCESS)
		return rv;

	/* Use access-list data structure to generate sequence. */
	dnode = yang_dnode_get(running_config->dnode, xpath);
	acl = nb_running_get_entry(dnode, NULL, true);
	if (seq_str == NULL) {
		sseq = filter_new_seq_get(acl);
		snprintf(xpath_entry, sizeof(xpath_entry),
			 "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintf(xpath_entry, sizeof(xpath_entry),
			 "%s/entry[sequence='%s']", xpath, seq_str);

	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value), "%s/action", xpath_entry);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, action);

	if (host_str != NULL && mask_str == NULL) {
		snprintf(xpath_value, sizeof(xpath_value), "%s/host",
			 xpath_entry);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, host_str);
	} else if (host_str != NULL && mask_str != NULL) {
		snprintf(xpath_value, sizeof(xpath_value), "%s/network",
			 xpath_entry);
		concat_addr_mask_v4(host_str, mask_str, ipmask, sizeof(ipmask));
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, ipmask);
	} else {
		snprintf(xpath_value, sizeof(xpath_value), "%s/any",
			 xpath_entry);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_access_list_std, no_access_list_std_cmd,
	"no access-list <(1-99)|(1300-1999)>$number [seq (1-4294967295)$seq] <deny|permit>$action <[host] A.B.C.D$host|A.B.C.D$host A.B.C.D$mask|any>",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_LEG_STR
	ACCESS_LIST_LEG_EXT_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"A single host address\n"
	"Address to match\n"
	"Address to match\n"
	"Wildcard bits\n"
	"Any source host\n")
{
	struct access_list *acl;
	struct lyd_node *dnode;
	int64_t sseq;
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 32];

	/* If the user provided sequence number, then just go for it. */
	if (seq_str != NULL) {
		snprintf(
			xpath, sizeof(xpath),
			"/frr-filter:lib/access-list-legacy[number='%s']/entry[sequence='%s']",
			number_str, seq_str);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	/* Otherwise, to keep compatibility, we need to figure it out. */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list-legacy[number='%s']", number_str);

	/* Access-list must exist before entries. */
	if (yang_dnode_exists(running_config->dnode, xpath) == false)
		return CMD_WARNING;

	/* Use access-list data structure to fetch sequence. */
	dnode = yang_dnode_get(running_config->dnode, xpath);
	acl = nb_running_get_entry(dnode, NULL, true);
	if (host_str != NULL)
		sseq = acl_cisco_get_seq(acl, action, host_str,
					 mask_str ? mask_str : "0.0.0.0", NULL,
					 NULL);
	else
		sseq = acl_cisco_get_seq(acl, action, "0.0.0.0",
					 "255.255.255.255", NULL, NULL);
	if (sseq == -1)
		return CMD_WARNING;

	snprintf(xpath_entry, sizeof(xpath_entry),
		 "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	access_list_ext, access_list_ext_cmd,
	"access-list <(100-199)|(2000-2699)>$number [seq (1-4294967295)$seq] <deny|permit>$action ip <A.B.C.D$src A.B.C.D$src_mask|host A.B.C.D$src|any> <A.B.C.D$dst A.B.C.D$dst_mask|host A.B.C.D$dst|any>",
	ACCESS_LIST_STR
	ACCESS_LIST_ELEG_STR
	ACCESS_LIST_ELEG_EXT_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"IPv4 address\n"
	"Source address to match\n"
	"Source address mask to apply\n"
	"Single source host\n"
	"Source address to match\n"
	"Any source host\n"
	"Destination address to match\n"
	"Destination address mask to apply\n"
	"Single destination host\n"
	"Destination address to match\n"
	"Any destination host\n")
{
	struct access_list *acl;
	struct lyd_node *dnode;
	int rv;
	int64_t sseq;
	char ipmask[64];
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 32];
	char xpath_value[XPATH_MAXLEN + 64];

	/*
	 * Create the access-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list-legacy[number='%s']", number_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	rv = nb_cli_apply_changes(vty, NULL);
	if (rv != CMD_SUCCESS)
		return rv;

	/* Use access-list data structure to generate sequence. */
	dnode = yang_dnode_get(running_config->dnode, xpath);
	acl = nb_running_get_entry(dnode, NULL, true);
	if (seq_str == NULL) {
		sseq = filter_new_seq_get(acl);
		snprintf(xpath_entry, sizeof(xpath_entry),
			 "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintf(xpath_entry, sizeof(xpath_entry),
			 "%s/entry[sequence='%s']", xpath, seq_str);

	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value), "%s/action", xpath_entry);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, action);

	if (src_str != NULL && src_mask_str == NULL) {
		snprintf(xpath_value, sizeof(xpath_value), "%s/host",
			 xpath_entry);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, src_str);
	} else if (src_str != NULL && src_mask_str != NULL) {
		snprintf(xpath_value, sizeof(xpath_value), "%s/network",
			 xpath_entry);
		concat_addr_mask_v4(src_str, src_mask_str, ipmask,
				    sizeof(ipmask));
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, ipmask);
	} else {
		snprintf(xpath_value, sizeof(xpath_value), "%s/any",
			 xpath_entry);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE, NULL);
	}

	if (dst_str != NULL && dst_mask_str == NULL) {
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/destination-host", xpath_entry);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, src_str);
	} else if (dst_str != NULL && dst_mask_str != NULL) {
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/destination-network", xpath_entry);
		concat_addr_mask_v4(dst_str, dst_mask_str, ipmask,
				    sizeof(ipmask));
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, ipmask);
	} else {
		snprintf(xpath_value, sizeof(xpath_value), "%s/destination-any",
			 xpath_entry);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_access_list_ext, no_access_list_ext_cmd,
	"no access-list <(100-199)|(2000-2699)>$number [seq (1-4294967295)$seq] <deny|permit>$action ip <A.B.C.D$src A.B.C.D$src_mask|host A.B.C.D$src|any> <A.B.C.D$dst A.B.C.D$dst_mask|host A.B.C.D$dst|any>",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ELEG_STR
	ACCESS_LIST_ELEG_EXT_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"Any Internet Protocol\n"
	"Source address to match\n"
	"Source address mask to apply\n"
	"Single source host\n"
	"Source address to match\n"
	"Any source host\n"
	"Destination address to match\n"
	"Destination address mask to apply\n"
	"Single destination host\n"
	"Destination address to match\n"
	"Any destination host\n")
{
	struct access_list *acl;
	struct lyd_node *dnode;
	int64_t sseq;
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 32];

	/* If the user provided sequence number, then just go for it. */
	if (seq_str != NULL) {
		snprintf(
			xpath, sizeof(xpath),
			"/frr-filter:lib/access-list-legacy[number='%s']/entry[sequence='%s']",
			number_str, seq_str);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	/* Otherwise, to keep compatibility, we need to figure it out. */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list-legacy[number='%s']", number_str);

	/* Access-list must exist before entries. */
	if (yang_dnode_exists(running_config->dnode, xpath) == false)
		return CMD_WARNING;

	/* Use access-list data structure to fetch sequence. */
	dnode = yang_dnode_get(running_config->dnode, xpath);
	acl = nb_running_get_entry(dnode, NULL, true);
	if (src_str != NULL) {
		if (dst_str != NULL)
			sseq = acl_cisco_get_seq(
				acl, action, src_str,
				src_mask_str ? src_mask_str : "0.0.0.0",
				dst_str,
				dst_mask_str ? dst_mask_str : "0.0.0.0");
		else
			sseq = acl_cisco_get_seq(acl, action, src_str,
						 src_mask_str ? src_mask_str
							      : "0.0.0.0",
						 "0.0.0.0", "255.255.255.255");
	} else {
		if (dst_str != NULL)
			sseq = acl_cisco_get_seq(acl, action, "0.0.0.0",
						 "255.255.255.255", dst_str,
						 dst_mask_str ? dst_mask_str
							      : "0.0.0.0");
		else
			sseq = acl_cisco_get_seq(acl, action, "0.0.0.0",
						 "255.255.255.255", "0.0.0.0",
						 "255.255.255.255");
	}
	if (sseq == -1)
		return CMD_WARNING;

	snprintf(xpath_entry, sizeof(xpath_entry),
		 "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_access_list_legacy, no_access_list_legacy_cmd,
	"no access-list <(1-99)|(100-199)|(1300-1999)|(2000-2699)>$number",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_XLEG_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list-legacy[number='%s']", number_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_access_list_legacy_seq, no_access_list_legacy_seq_cmd,
	"no access-list <(1-99)|(100-199)|(1300-1999)|(2000-2699)>$number seq (1-4294967295)$seq",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_XLEG_STR
	ACCESS_LIST_SEQ_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list-legacy[number='%s']/entry[sequence='%s']",
		 number_str, seq_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	access_list_legacy_remark, access_list_legacy_remark_cmd,
	"access-list <(1-99)|(100-199)|(1300-1999)|(2000-2699)>$number remark LINE...",
	ACCESS_LIST_STR
	ACCESS_LIST_XLEG_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)
{
	int rv;
	char *remark;
	char xpath[XPATH_MAXLEN];
	char xpath_remark[XPATH_MAXLEN + 32];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list-legacy[number='%s']", number_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_remark, sizeof(xpath_remark), "%s/remark", xpath);
	remark = argv_concat(argv, argc, 3);
	nb_cli_enqueue_change(vty, xpath_remark, NB_OP_CREATE, remark);
	rv = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, remark);

	return rv;
}

DEFPY(
	no_access_list_legacy_remark, no_access_list_legacy_remark_cmd,
	"no access-list <(1-99)|(100-199)|(1300-1999)|(2000-2699)>$number remark",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_XLEG_STR
	ACCESS_LIST_REMARK_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list-legacy[number='%s']/remark",
		 number_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS(
	no_access_list_legacy_remark, no_access_list_legacy_remark_line_cmd,
	"no access-list <(1-99)|(100-199)|(1300-1999)|(2000-2699)>$number remark LINE...",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_XLEG_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)

/*
 * Zebra access lists.
 */
DEFPY(
	access_list, access_list_cmd,
	"access-list WORD$name [seq (1-4294967295)$seq] <deny|permit>$action <A.B.C.D/M$prefix [exact-match$exact]|any>",
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"Prefix to match. e.g. 10.0.0.0/8\n"
	"Exact match of the prefixes\n"
	"Match any IPv4\n")
{
	struct access_list *acl;
	struct lyd_node *dnode;
	int rv;
	int64_t sseq;
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 32];
	char xpath_value[XPATH_MAXLEN + 64];

	/*
	 * Create the access-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv4'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	rv = nb_cli_apply_changes(vty, NULL);
	if (rv != CMD_SUCCESS)
		return rv;

	/* Use access-list data structure to generate sequence. */
	dnode = yang_dnode_get(running_config->dnode, xpath);
	acl = nb_running_get_entry(dnode, NULL, true);
	if (seq_str == NULL) {
		sseq = filter_new_seq_get(acl);
		snprintf(xpath_entry, sizeof(xpath_entry),
			 "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintf(xpath_entry, sizeof(xpath_entry),
			 "%s/entry[sequence='%s']", xpath, seq_str);

	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value), "%s/action", xpath_entry);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, action);

	if (prefix_str != NULL) {
		snprintf(xpath_value, sizeof(xpath_value), "%s/ipv4-prefix",
			 xpath_entry);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
				      prefix_str);

		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/ipv4-exact-match", xpath_entry);
		if (exact)
			nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE,
					      NULL);
		else
			nb_cli_enqueue_change(vty, xpath_value, NB_OP_DESTROY,
					      NULL);
	} else {
		snprintf(xpath_value, sizeof(xpath_value), "%s/any",
			 xpath_entry);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_access_list, no_access_list_cmd,
	"no access-list WORD$name [seq (1-4294967295)$seq] <deny|permit>$action <A.B.C.D/M$prefix [exact-match$exact]|any>",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"Prefix to match. e.g. 10.0.0.0/8\n"
	"Exact match of the prefixes\n"
	"Match any IPv4\n")
{
	struct access_list *acl;
	struct lyd_node *dnode;
	int64_t sseq;
	struct prefix pany;
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 32];

	/* If the user provided sequence number, then just go for it. */
	if (seq_str != NULL) {
		snprintf(
			xpath, sizeof(xpath),
			"/frr-filter:lib/access-list[type='ipv4'][name='%s']/entry[sequence='%s']",
			name, seq_str);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	/* Otherwise, to keep compatibility, we need to figure it out. */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv4'][name='%s']", name);

	/* Access-list must exist before entries. */
	if (yang_dnode_exists(running_config->dnode, xpath) == false)
		return CMD_WARNING;

	/* Use access-list data structure to fetch sequence. */
	dnode = yang_dnode_get(running_config->dnode, xpath);
	acl = nb_running_get_entry(dnode, NULL, true);
	if (prefix == NULL) {
		memset(&pany, 0, sizeof(pany));
		pany.family = AF_INET;
		sseq = acl_zebra_get_seq(acl, action, &pany, exact);
	} else
		sseq = acl_zebra_get_seq(acl, action, (struct prefix *)prefix,
					 exact);
	if (sseq == -1)
		return CMD_WARNING;

	snprintf(xpath_entry, sizeof(xpath_entry),
		 "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_access_list_seq, no_access_list_seq_cmd,
	"no access-list WORD$name seq (1-4294967295)$seq",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv4'][name='%s']/entry[sequence='%s']",
		 name, seq_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_access_list_all, no_access_list_all_cmd,
	"no access-list WORD$name",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv4'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	access_list_remark, access_list_remark_cmd,
	"access-list WORD$name remark LINE...",
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)
{
	int rv;
	char *remark;
	char xpath[XPATH_MAXLEN];
	char xpath_remark[XPATH_MAXLEN + 32];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv4'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_remark, sizeof(xpath_remark), "%s/remark", xpath);
	remark = argv_concat(argv, argc, 3);
	nb_cli_enqueue_change(vty, xpath_remark, NB_OP_CREATE, remark);
	rv = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, remark);

	return rv;
}

DEFPY(
	no_access_list_remark, no_access_list_remark_cmd,
	"no access-list WORD$name remark",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv4'][name='%s']/remark",
		 name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS(
	no_access_list_remark, no_access_list_remark_line_cmd,
	"no access-list WORD$name remark LINE...",
	NO_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)

DEFPY(
	ipv6_access_list, ipv6_access_list_cmd,
	"ipv6 access-list WORD$name [seq (1-4294967295)$seq] <deny|permit>$action <X:X::X:X/M$prefix [exact-match$exact]|any>",
	IPV6_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"IPv6 prefix\n"
	"Exact match of the prefixes\n"
	"Match any IPv6\n")
{
	struct access_list *acl;
	struct lyd_node *dnode;
	int rv;
	int64_t sseq;
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 32];
	char xpath_value[XPATH_MAXLEN + 64];

	/*
	 * Create the access-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv6'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	rv = nb_cli_apply_changes(vty, NULL);
	if (rv != CMD_SUCCESS)
		return rv;

	/* Use access-list data structure to generate sequence. */
	dnode = yang_dnode_get(running_config->dnode, xpath);
	acl = nb_running_get_entry(dnode, NULL, true);
	if (seq_str == NULL) {
		sseq = filter_new_seq_get(acl);
		snprintf(xpath_entry, sizeof(xpath_entry),
			 "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintf(xpath_entry, sizeof(xpath_entry),
			 "%s/entry[sequence='%s']", xpath, seq_str);

	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value), "%s/action", xpath_entry);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, action);

	if (prefix_str != NULL) {
		snprintf(xpath_value, sizeof(xpath_value), "%s/ipv6-prefix",
			 xpath_entry);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
				      prefix_str);

		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/ipv6-exact-match", xpath_entry);
		if (exact)
			nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE,
					      NULL);
		else
			nb_cli_enqueue_change(vty, xpath_value, NB_OP_DESTROY,
					      NULL);
	} else {
		snprintf(xpath_value, sizeof(xpath_value), "%s/any",
			 xpath_entry);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_ipv6_access_list, no_ipv6_access_list_cmd,
	"no ipv6 access-list WORD$name [seq (1-4294967295)$seq] <deny|permit>$action <X:X::X:X/M$prefix [exact-match$exact]|any>",
	NO_STR
	IPV6_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"IPv6 prefix\n"
	"Exact match of the prefixes\n"
	"Match any IPv6\n")
{
	struct access_list *acl;
	struct lyd_node *dnode;
	int64_t sseq;
	struct prefix pany;
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 32];

	/* If the user provided sequence number, then just go for it. */
	if (seq_str != NULL) {
		snprintf(
			xpath, sizeof(xpath),
			"/frr-filter:lib/access-list[type='ipv6'][name='%s']/entry[sequence='%s']",
			name, seq_str);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	/* Otherwise, to keep compatibility, we need to figure it out. */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv6'][name='%s']", name);

	/* Access-list must exist before entries. */
	if (yang_dnode_exists(running_config->dnode, xpath) == false)
		return CMD_WARNING;

	/* Use access-list data structure to fetch sequence. */
	dnode = yang_dnode_get(running_config->dnode, xpath);
	acl = nb_running_get_entry(dnode, NULL, true);
	if (prefix == NULL) {
		memset(&pany, 0, sizeof(pany));
		pany.family = AF_INET6;
		sseq = acl_zebra_get_seq(acl, action, &pany, exact);
	} else
		sseq = acl_zebra_get_seq(acl, action, (struct prefix *)prefix,
					 exact);
	if (sseq == -1)
		return CMD_WARNING;

	snprintf(xpath_entry, sizeof(xpath_entry),
		 "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_ipv6_access_list_all, no_ipv6_access_list_all_cmd,
	"no ipv6 access-list WORD$name",
	NO_STR
	IPV6_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv6'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_ipv6_access_list_seq, no_ipv6_access_list_seq_cmd,
	"no ipv6 access-list WORD$name seq (1-4294967295)$seq",
	NO_STR
	IPV6_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv6'][name='%s']/entry[sequence='%s']",
		 name, seq_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	ipv6_access_list_remark, ipv6_access_list_remark_cmd,
	"ipv6 access-list WORD$name remark LINE...",
	IPV6_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)
{
	int rv;
	char *remark;
	char xpath[XPATH_MAXLEN];
	char xpath_remark[XPATH_MAXLEN + 32];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv6'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_remark, sizeof(xpath_remark), "%s/remark", xpath);
	remark = argv_concat(argv, argc, 4);
	nb_cli_enqueue_change(vty, xpath_remark, NB_OP_CREATE, remark);
	rv = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, remark);

	return rv;
}

DEFPY(
	no_ipv6_access_list_remark, no_ipv6_access_list_remark_cmd,
	"no ipv6 access-list WORD$name remark",
	NO_STR
	IPV6_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='ipv6'][name='%s']/remark",
		 name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS(
	no_ipv6_access_list_remark, no_ipv6_access_list_remark_line_cmd,
	"no ipv6 access-list WORD$name remark LINE...",
	NO_STR
	IPV6_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)

DEFPY(
	mac_access_list, mac_access_list_cmd,
	"mac access-list WORD$name [seq (1-4294967295)$seq] <deny|permit>$action <X:X:X:X:X:X$mac|any>",
	MAC_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"MAC address\n"
	"Match any MAC address\n")
{
	struct access_list *acl;
	struct lyd_node *dnode;
	int rv;
	int64_t sseq;
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 32];
	char xpath_value[XPATH_MAXLEN + 64];

	/*
	 * Create the access-list first, so we can generate sequence if
	 * none given (backward compatibility).
	 */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='mac'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	rv = nb_cli_apply_changes(vty, NULL);
	if (rv != CMD_SUCCESS)
		return rv;

	/* Use access-list data structure to generate sequence. */
	dnode = yang_dnode_get(running_config->dnode, xpath);
	acl = nb_running_get_entry(dnode, NULL, true);
	if (seq_str == NULL) {
		sseq = filter_new_seq_get(acl);
		snprintf(xpath_entry, sizeof(xpath_entry),
			 "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	} else
		snprintf(xpath_entry, sizeof(xpath_entry),
			 "%s/entry[sequence='%s']", xpath, seq_str);

	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value), "%s/action", xpath_entry);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, action);

	if (mac_str != NULL) {
		snprintf(xpath_value, sizeof(xpath_value), "%s/mac",
			 xpath_entry);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, mac_str);
	} else {
		snprintf(xpath_value, sizeof(xpath_value), "%s/any",
			 xpath_entry);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_mac_access_list, no_mac_access_list_cmd,
	"no mac access-list WORD$name [seq (1-4294967295)$seq] <deny|permit>$action <X:X::X:X/M$prefix [exact-match$exact]|any>",
	NO_STR
	MAC_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR
	ACCESS_LIST_ACTION_STR
	"MAC address\n"
	"Exact match of the prefixes\n"
	"Match any MAC address\n")
{
	struct access_list *acl;
	struct lyd_node *dnode;
	int64_t sseq;
	struct prefix pany;
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 32];

	/* If the user provided sequence number, then just go for it. */
	if (seq_str != NULL) {
		snprintf(
			xpath, sizeof(xpath),
			"/frr-filter:lib/access-list[type='mac'][name='%s']/entry[sequence='%s']",
			name, seq_str);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		return nb_cli_apply_changes(vty, NULL);
	}

	/* Otherwise, to keep compatibility, we need to figure it out. */
	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='mac'][name='%s']", name);

	/* Access-list must exist before entries. */
	if (yang_dnode_exists(running_config->dnode, xpath) == false)
		return CMD_WARNING;

	/* Use access-list data structure to fetch sequence. */
	dnode = yang_dnode_get(running_config->dnode, xpath);
	acl = nb_running_get_entry(dnode, NULL, true);
	if (prefix == NULL) {
		memset(&pany, 0, sizeof(pany));
		pany.family = AF_ETHERNET;
		sseq = acl_zebra_get_seq(acl, action, &pany, exact);
	} else
		sseq = acl_zebra_get_seq(acl, action, (struct prefix *)prefix,
					 exact);
	if (sseq == -1)
		return CMD_WARNING;

	snprintf(xpath_entry, sizeof(xpath_entry),
		 "%s/entry[sequence='%" PRId64 "']", xpath, sseq);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_mac_access_list_all, no_mac_access_list_all_cmd,
	"no mac access-list WORD$name",
	NO_STR
	MAC_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='mac'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	no_mac_access_list_seq, no_mac_access_list_seq_cmd,
	"no mac access-list WORD$name seq (1-4294967295)$seq",
	NO_STR
	MAC_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_SEQ_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='mac'][name='%s']/entry[sequence='%s']",
		 name, seq_str);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(
	mac_access_list_remark, mac_access_list_remark_cmd,
	"mac access-list WORD$name remark LINE...",
	MAC_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)
{
	int rv;
	char *remark;
	char xpath[XPATH_MAXLEN];
	char xpath_remark[XPATH_MAXLEN + 32];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='mac'][name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_remark, sizeof(xpath_remark), "%s/remark", xpath);
	remark = argv_concat(argv, argc, 4);
	nb_cli_enqueue_change(vty, xpath_remark, NB_OP_CREATE, remark);
	rv = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, remark);

	return rv;
}

DEFPY(
	no_mac_access_list_remark, no_mac_access_list_remark_cmd,
	"no mac access-list WORD$name remark",
	NO_STR
	MAC_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-filter:lib/access-list[type='mac'][name='%s']/remark",
		 name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

ALIAS(
	no_mac_access_list_remark, no_mac_access_list_remark_line_cmd,
	"no mac access-list WORD$name remark LINE...",
	NO_STR
	MAC_STR
	ACCESS_LIST_STR
	ACCESS_LIST_ZEBRA_STR
	ACCESS_LIST_REMARK_STR
	ACCESS_LIST_REMARK_LINE_STR)

void filter_cli_init(void)
{
	/* access-list cisco-style (legacy). */
	install_element(CONFIG_NODE, &access_list_std_cmd);
	install_element(CONFIG_NODE, &no_access_list_std_cmd);
	install_element(CONFIG_NODE, &access_list_ext_cmd);
	install_element(CONFIG_NODE, &no_access_list_ext_cmd);
	install_element(CONFIG_NODE, &no_access_list_legacy_cmd);
	install_element(CONFIG_NODE, &no_access_list_legacy_seq_cmd);
	install_element(CONFIG_NODE, &access_list_legacy_remark_cmd);
	install_element(CONFIG_NODE, &no_access_list_legacy_remark_cmd);
	install_element(CONFIG_NODE, &no_access_list_legacy_remark_line_cmd);

	/* access-list zebra-style. */
	install_element(CONFIG_NODE, &access_list_cmd);
	install_element(CONFIG_NODE, &no_access_list_cmd);
	install_element(CONFIG_NODE, &no_access_list_all_cmd);
	install_element(CONFIG_NODE, &no_access_list_seq_cmd);
	install_element(CONFIG_NODE, &access_list_remark_cmd);
	install_element(CONFIG_NODE, &no_access_list_remark_cmd);
	install_element(CONFIG_NODE, &no_access_list_remark_line_cmd);

	install_element(CONFIG_NODE, &ipv6_access_list_cmd);
	install_element(CONFIG_NODE, &no_ipv6_access_list_cmd);
	install_element(CONFIG_NODE, &no_ipv6_access_list_all_cmd);
	install_element(CONFIG_NODE, &no_ipv6_access_list_seq_cmd);
	install_element(CONFIG_NODE, &ipv6_access_list_remark_cmd);
	install_element(CONFIG_NODE, &no_ipv6_access_list_remark_cmd);
	install_element(CONFIG_NODE, &no_ipv6_access_list_remark_line_cmd);

	install_element(CONFIG_NODE, &mac_access_list_cmd);
	install_element(CONFIG_NODE, &no_mac_access_list_cmd);
	install_element(CONFIG_NODE, &no_mac_access_list_all_cmd);
	install_element(CONFIG_NODE, &no_mac_access_list_seq_cmd);
	install_element(CONFIG_NODE, &mac_access_list_remark_cmd);
	install_element(CONFIG_NODE, &no_mac_access_list_remark_cmd);
	install_element(CONFIG_NODE, &no_mac_access_list_remark_line_cmd);
}
