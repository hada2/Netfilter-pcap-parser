import sys
import dpkt, socket
from struct import pack, unpack

u64  = lambda x: unpack("<Q", x)[0]
u32  = lambda x: unpack("<I", x)[0]
u16  = lambda x: unpack("<H", x)[0]
u8   = lambda x: unpack("<B", x)[0]
u64b = lambda x: unpack(">Q", x)[0]
u32b = lambda x: unpack(">I", x)[0]
u16b = lambda x: unpack(">H", x)[0]
u8b  = lambda x: unpack(">B", x)[0]

# Attribute data type
(NLA_UNSPEC, NLA_U8, NLA_U16, NLA_U32, NLA_U64, NLA_STRING, NLA_FLAG, NLA_MSECS, NLA_NESTED, NLA_NESTED_COMPAT, NLA_NUL_STRING, NLA_BINARY, NLA_S8, NLA_S16, NLA_S32, NLA_S64) = range(16)

# Protocol family
SA_FAMILY = [
    "AF_UNSPEC",
    "AF_UNIX",
    "AF_INET",
    "AF_AX25",
    "AF_IPX",
    "AF_APPLETALK",
    "AF_NETROM",
    "AF_BRIDGE",
    "AF_ATMPVC",
    "AF_X25",
    "AF_INET6",
    "AF_ROSE",
    "AF_DECnet",
    "AF_NETBEUI",
    "AF_SECURITY",
    "AF_KEY",
    "AF_NETLINK",
    "AF_PACKET",
    "AF_ASH",
    "AF_ECONET",
    "AF_ATMSVC",
    "AF_RDS",
    "AF_SNA",
    "AF_IRDA",
    "AF_PPPOX",
    "AF_WANPIPE",
    "AF_LLC",
    "AF_IB",
    "AF_MPLS",
    "AF_CAN",
    "AF_TIPC",
    "AF_BLUETOOTH",
    "AF_IUCV",
    "AF_RXRPC",
    "AF_ISDN",
    "AF_PHONET",
    "AF_IEEE802154",
    "AF_CAIF",
    "AF_ALG",
    "AF_NFC",
    "AF_VSOCK",
    "AF_KCM",
    "AF_QIPCRTR",
    "AF_SMC",
    "AF_XDP",
    "AF_MCTP",
    "AF_MAX"
]

# const
nft_registers = [
	"NFT_REG_VERDICT",
	"NFT_REG_1",
	"NFT_REG_2",
	"NFT_REG_3",
	"NFT_REG_4",
	None,
    None,
    None,
	"NFT_REG32_00",
	"NFT_REG32_01",
	"NFT_REG32_02",
	"NFT_REG32_03",
	"NFT_REG32_04",
	"NFT_REG32_05",
	"NFT_REG32_06",
	"NFT_REG32_07",
	"NFT_REG32_08",
	"NFT_REG32_09",
	"NFT_REG32_10",
	"NFT_REG32_11",
	"NFT_REG32_12",
	"NFT_REG32_13",
	"NFT_REG32_14",
	"NFT_REG32_15",
]

nft_payload_bases = [
	"NFT_PAYLOAD_LL_HEADER",
	"NFT_PAYLOAD_NETWORK_HEADER",
	"NFT_PAYLOAD_TRANSPORT_HEADER",
]

nft_cmp_ops = [
	"NFT_CMP_EQ",
	"NFT_CMP_NEQ",
	"NFT_CMP_LT",
	"NFT_CMP_LTE",
	"NFT_CMP_GT",
	"NFT_CMP_GTE",
]

nft_bitwise_ops = [
	"NFT_BITWISE_BOOL",
	"NFT_BITWISE_LSHIFT",
	"NFT_BITWISE_RSHIFT",
]

nft_meta_keys = [
    "NFT_META_LEN",
    "NFT_META_PROTOCOL",
    "NFT_META_PRIORITY",
    "NFT_META_MARK",
    "NFT_META_IIF",
    "NFT_META_OIF",
    "NFT_META_IIFNAME",
    "NFT_META_OIFNAME",
    "NFT_META_IIFTYPE",
    "NFT_META_OIFTYPE",
    "NFT_META_SKUID",
    "NFT_META_SKGID",
    "NFT_META_NFTRACE",
    "NFT_META_RTCLASSID",
    "NFT_META_SECMARK",
    "NFT_META_NFPROTO",
    "NFT_META_L4PROTO",
    "NFT_META_BRI_IIFNAME",
    "NFT_META_BRI_OIFNAME",
    "NFT_META_PKTTYPE",
    "NFT_META_CPU",
    "NFT_META_IIFGROUP",
    "NFT_META_OIFGROUP",
    "NFT_META_CGROUP",
    "NFT_META_PRANDOM",
    "NFT_META_SECPATH",
    "NFT_META_IIFKIND",
    "NFT_META_OIFKIND",
    "NFT_META_BRI_IIFPVID",
    "NFT_META_BRI_IIFVPROTO",
    "NFT_META_TIME_NS",
    "NFT_META_TIME_DAY",
    "NFT_META_TIME_HOUR",
    "NFT_META_SDIF",
    "NFT_META_SDIFNAME",
]

nft_limit_type = [
	"NFT_LIMIT_PKTS",
	"NFT_LIMIT_PKT_BYTES",
]

nft_log_level = [
	"NFT_LOGLEVEL_EMERG",
	"NFT_LOGLEVEL_ALERT",
	"NFT_LOGLEVEL_CRIT",
	"NFT_LOGLEVEL_ERR",
	"NFT_LOGLEVEL_WARNING",
	"NFT_LOGLEVEL_NOTICE",
	"NFT_LOGLEVEL_INFO",
	"NFT_LOGLEVEL_DEBUG",
	"NFT_LOGLEVEL_AUDIT",
]

nft_reject_types = [
	"NFT_REJECT_ICMP_UNREACH",
	"NFT_REJECT_TCP_RST",
	"NFT_REJECT_ICMPX_UNREACH",
]

nft_nat_types = [
	"NFT_NAT_SNAT",
	"NFT_NAT_DNAT",
]

nft_exthdr_op = [
	"NFT_EXTHDR_OP_IPV6",
	"NFT_EXTHDR_OP_TCPOPT",
	"NFT_EXTHDR_OP_IPV4",
	"NFT_EXTHDR_OP_SCTP",
]

nft_ng_types = [
	"NFT_NG_INCREMENTAL",
	"NFT_NG_RANDOM",
]

nft_fib_result = [
	"NFT_FIB_RESULT_UNSPEC",
	"NFT_FIB_RESULT_OIF",
	"NFT_FIB_RESULT_OIFNAME",
	"NFT_FIB_RESULT_ADDRTYPE",
]

# Attribute Types
nft_verdict_attributes = [
	("NFTA_VERDICT_UNSPEC", None),
	("NFTA_VERDICT_CODE", None),
	("NFTA_VERDICT_CHAIN", NLA_STRING),
	("NFTA_VERDICT_CHAIN_ID", NLA_U32),
]

nft_hook_attributes = [
	("NFTA_HOOK_UNSPEC", None),
	("NFTA_HOOK_HOOKNUM", NLA_U32),
	("NFTA_HOOK_PRIORITY", NLA_U32),
	("NFTA_HOOK_DEV", NLA_STRING),
	("NFTA_HOOK_DEVS", NLA_NESTED, None),
]

nft_counter_attributes = [
	("NFTA_COUNTER_UNSPEC", None),
	("NFTA_COUNTER_BYTES", NLA_U64),
	("NFTA_COUNTER_PACKETS", NLA_U64),
	("NFTA_COUNTER_PAD", None),
]

nft_rule_compat_attributes = [
	("NFTA_RULE_COMPAT_UNSPEC", None),
	("NFTA_RULE_COMPAT_PROTO", NLA_U32),
	("NFTA_RULE_COMPAT_FLAGS", NLA_U32),
]

nft_data_attributes = [
	("NFTA_DATA_UNSPEC", None),
	("NFTA_DATA_VALUE", NLA_BINARY),
	("NFTA_DATA_VERDICT", NLA_NESTED, nft_verdict_attributes),
]

nft_table_attributes = [
    ("NFTA_TABLE_UNSPEC", None),
    ("NFTA_TABLE_NAME", NLA_STRING),
    ("NFTA_TABLE_FLAGS", NLA_U32),
    ("NFTA_TABLE_USE", NLA_U32),
    ("NFTA_TABLE_HANDLE", NLA_U64),
    ("NFTA_TABLE_PAD", None),
    ("NFTA_TABLE_USERDATA", NLA_BINARY),
    ("NFTA_TABLE_OWNER", NLA_U32),
]

nft_chain_attributes = [
    ("NFTA_CHAIN_UNSPEC", None),
	("NFTA_CHAIN_TABLE", NLA_STRING),
	("NFTA_CHAIN_HANDLE", NLA_U64),
	("NFTA_CHAIN_NAME", NLA_STRING),
	("NFTA_CHAIN_HOOK", NLA_NESTED, nft_hook_attributes),
	("NFTA_CHAIN_POLICY", NLA_U32),
	("NFTA_CHAIN_USE", NLA_U32),
	("NFTA_CHAIN_TYPE", NLA_NUL_STRING),
	("NFTA_CHAIN_COUNTERS", NLA_NESTED, nft_counter_attributes),
	("NFTA_CHAIN_PAD", None),
	("NFTA_CHAIN_FLAGS", None),
	("NFTA_CHAIN_ID", NLA_U32),
	("NFTA_CHAIN_USERDATA", NLA_BINARY),
]

nft_expr_attributes = [
	("NFTA_EXPR_UNSPEC", None),
	("NFTA_EXPR_NAME", NLA_STRING),
	("NFTA_EXPR_DATA", NLA_NESTED, None),
]

nft_rule_attributes = [
	("NFTA_RULE_UNSPEC", None),
	("NFTA_RULE_TABLE", NLA_STRING),
	("NFTA_RULE_CHAIN", NLA_STRING),
	("NFTA_RULE_HANDLE", NLA_U64),
	("NFTA_RULE_EXPRESSIONS", NLA_NESTED,
        [
        	("NFTA_LIST_UNSPEC", None),
        	("NFTA_LIST_ELEM", NLA_NESTED, nft_expr_attributes),
        ]),
	("NFTA_RULE_COMPAT", NLA_NESTED, nft_rule_compat_attributes),
	("NFTA_RULE_POSITION", NLA_U64),
	("NFTA_RULE_USERDATA", None),
	("NFTA_RULE_PAD", None),
	("NFTA_RULE_ID", NLA_U32),
	("NFTA_RULE_POSITION_ID", NLA_U32),
	("NFTA_RULE_CHAIN_ID", None),
]

nft_set_attributes = [
	("NFTA_SET_UNSPEC", None),
	("NFTA_SET_TABLE", NLA_STRING),
	("NFTA_SET_NAME", NLA_STRING),
	("NFTA_SET_FLAGS", NLA_U32),
	("NFTA_SET_KEY_TYPE", NLA_U32),
	("NFTA_SET_KEY_LEN", NLA_U32),
	("NFTA_SET_DATA_TYPE", NLA_U32),
	("NFTA_SET_DATA_LEN", NLA_U32),
	("NFTA_SET_POLICY", NLA_U32),
	("NFTA_SET_DESC", NLA_NESTED, None),
	("NFTA_SET_ID", NLA_U32),
	("NFTA_SET_TIMEOUT", NLA_U64),
	("NFTA_SET_GC_INTERVAL", NLA_U32),
	("NFTA_SET_USERDATA", NLA_BINARY),
	("NFTA_SET_PAD", None),
	("NFTA_SET_OBJ_TYPE", None),
	("NFTA_SET_HANDLE", NLA_U64),
	("NFTA_SET_EXPR", NLA_NESTED, nft_expr_attributes),
	("NFTA_SET_EXPRESSIONS", NLA_NESTED,
        [
        	("NFTA_LIST_UNSPEC", None),
        	("NFTA_LIST_ELEM", NLA_NESTED, None),
        ]
    ),
]

nft_set_elem_attributes = [
	("NFTA_SET_ELEM_UNSPEC", None),
	("NFTA_SET_ELEM_KEY", NLA_NESTED, nft_data_attributes), # guess
	("NFTA_SET_ELEM_DATA", NLA_NESTED, nft_data_attributes),
	("NFTA_SET_ELEM_FLAGS", NLA_U32),
	("NFTA_SET_ELEM_TIMEOUT", NLA_U64),
	("NFTA_SET_ELEM_EXPIRATION", NLA_U64),
	("NFTA_SET_ELEM_USERDATA", NLA_BINARY),
	("NFTA_SET_ELEM_EXPR", NLA_NESTED, nft_expr_attributes),
	("NFTA_SET_ELEM_PAD", None),
	("NFTA_SET_ELEM_OBJREF", NLA_STRING),
	("NFTA_SET_ELEM_KEY_END", NLA_NESTED, nft_data_attributes), # guess
	("NFTA_SET_ELEM_EXPRESSIONS", NLA_NESTED,
        [
        	("NFTA_LIST_UNSPEC", None),
        	("NFTA_LIST_ELEM", NLA_NESTED, None),
        ]
    ),
]

nft_set_elem_list_attributes = [
	("NFTA_SET_ELEM_LIST_UNSPEC", None),
	("NFTA_SET_ELEM_LIST_TABLE", NLA_STRING),
	("NFTA_SET_ELEM_LIST_SET", NLA_STRING),
	("NFTA_SET_ELEM_LIST_ELEMENTS", NLA_NESTED,
        [
        	("NFTA_LIST_UNSPEC", None),
        	("NFTA_LIST_ELEM", NLA_NESTED, nft_set_elem_attributes),
        ]),
	("NFTA_SET_ELEM_LIST_SET_ID", NLA_U32),
]

nft_gen_attributes = [
	("NFTA_GEN_UNSPEC", None),
	("NFTA_GEN_ID", NLA_U32),
	("NFTA_GEN_PROC_PID", None),
	("NFTA_GEN_PROC_NAME", NLA_STRING),
]

nft_trace_attributes = [
	("NFTA_TRACE_UNSPEC", None),
	("NFTA_TRACE_TABLE", NLA_STRING),
	("NFTA_TRACE_CHAIN", NLA_STRING),
	("NFTA_TRACE_RULE_HANDLE", NLA_U64),
	("NFTA_TRACE_TYPE", None),
	("NFTA_TRACE_VERDICT", NLA_NESTED, None), # nft_verdicts
	("NFTA_TRACE_ID", NLA_U32),
	("NFTA_TRACE_LL_HEADER", NLA_BINARY),
	("NFTA_TRACE_NETWORK_HEADER", NLA_BINARY),
	("NFTA_TRACE_TRANSPORT_HEADER", NLA_BINARY),
	("NFTA_TRACE_IIF", NLA_U32),
	("NFTA_TRACE_IIFTYPE", NLA_U16),
	("NFTA_TRACE_OIF", NLA_U32),
	("NFTA_TRACE_OIFTYPE", NLA_U16),
	("NFTA_TRACE_MARK", NLA_U32),
	("NFTA_TRACE_NFPROTO", NLA_U32),
	("NFTA_TRACE_POLICY", NLA_U32),
	("NFTA_TRACE_PAD", None),
]

nft_object_attributes = [
	("NFTA_OBJ_UNSPEC", None),
	("NFTA_OBJ_TABLE", NLA_STRING),
	("NFTA_OBJ_NAME", NLA_STRING),
	("NFTA_OBJ_TYPE", NLA_U32),
	("NFTA_OBJ_DATA", NLA_NESTED, None),
	("NFTA_OBJ_USE", NLA_U32),
	("NFTA_OBJ_HANDLE", NLA_U64),
	("NFTA_OBJ_PAD", None),
	("NFTA_OBJ_USERDATA", NLA_BINARY),
]

nft_flowtable_attributes = [
	("NFTA_FLOWTABLE_UNSPEC", None),
	("NFTA_FLOWTABLE_TABLE", NLA_STRING),
	("NFTA_FLOWTABLE_NAME", NLA_STRING),
	("NFTA_FLOWTABLE_HOOK", NLA_U32),
	("NFTA_FLOWTABLE_USE", NLA_U32),
	("NFTA_FLOWTABLE_HANDLE", NLA_U64),
	("NFTA_FLOWTABLE_PAD", None),
	("NFTA_FLOWTABLE_FLAGS", NLA_U32),
]

nft_objref_attributes = [
	("NFTA_OBJREF_UNSPEC", None),
	("NFTA_OBJREF_IMM_TYPE", None),
	("NFTA_OBJREF_IMM_NAME", NLA_STRING),
	("NFTA_OBJREF_SET_SREG", None),
	("NFTA_OBJREF_SET_NAME", NLA_STRING),
	("NFTA_OBJREF_SET_ID", NLA_U32),
]

nft_immediate_attributes = [
	("NFTA_IMMEDIATE_UNSPEC", None),
	("NFTA_IMMEDIATE_DREG", NLA_U32),
	("NFTA_IMMEDIATE_DATA", NLA_NESTED, nft_data_attributes),
]

nft_payload_attributes = [
	("NFTA_PAYLOAD_UNSPEC", None),
	("NFTA_PAYLOAD_DREG", NLA_U32, nft_registers),
	("NFTA_PAYLOAD_BASE", NLA_U32, nft_payload_bases),
	("NFTA_PAYLOAD_OFFSET", NLA_U32),
	("NFTA_PAYLOAD_LEN", NLA_U32),
	("NFTA_PAYLOAD_SREG", NLA_U32, nft_registers),
	("NFTA_PAYLOAD_CSUM_TYPE", NLA_U32),
	("NFTA_PAYLOAD_CSUM_OFFSET", NLA_U32),
	("NFTA_PAYLOAD_CSUM_FLAGS", NLA_U32),
]

nft_cmp_attributes = [
	("NFTA_CMP_UNSPEC", None),
	("NFTA_CMP_SREG", NLA_U32, nft_registers),
	("NFTA_CMP_OP", NLA_U32, nft_cmp_ops),
	("NFTA_CMP_DATA", NLA_NESTED, nft_data_attributes),
]

nft_lookup_attributes = [
	("NFTA_LOOKUP_UNSPEC", None),
	("NFTA_LOOKUP_SET", NLA_STRING),
	("NFTA_LOOKUP_SREG", NLA_U32, nft_registers),
	("NFTA_LOOKUP_DREG", NLA_U32, nft_registers),
	("NFTA_LOOKUP_SET_ID", NLA_U32),
	("NFTA_LOOKUP_FLAGS", None),
]

nft_bitwise_attributes = [
	("NFTA_BITWISE_UNSPEC", None),
	("NFTA_BITWISE_SREG", NLA_U32, nft_registers),
	("NFTA_BITWISE_DREG", NLA_U32, nft_registers),
	("NFTA_BITWISE_LEN", NLA_U32),
	("NFTA_BITWISE_MASK", NLA_NESTED, nft_data_attributes),
	("NFTA_BITWISE_XOR", NLA_NESTED, nft_data_attributes),
	("NFTA_BITWISE_OP", NLA_U32, nft_bitwise_ops),
	("NFTA_BITWISE_DATA", None),
]

nft_meta_attributes = [
	("NFTA_META_UNSPEC", None),
	("NFTA_META_DREG", NLA_U32),
	("NFTA_META_KEY", NLA_U32, nft_meta_keys),
	("NFTA_META_SREG", NLA_U32),
]

nft_limit_attributes = [
	("NFTA_LIMIT_UNSPEC", None),
	("NFTA_LIMIT_RATE", NLA_U64),
	("NFTA_LIMIT_UNIT", NLA_U64),
	("NFTA_LIMIT_BURST", NLA_U32),
	("NFTA_LIMIT_TYPE", NLA_U32, nft_limit_type), # guess
	("NFTA_LIMIT_FLAGS", None),
	("NFTA_LIMIT_PAD", None),
]

nft_connlimit_attributes = [
	("NFTA_CONNLIMIT_UNSPEC", None),
	("NFTA_CONNLIMIT_COUNT", NLA_U32),
	("NFTA_CONNLIMIT_FLAGS", None),
]

nft_log_attributes = [
	("NFTA_LOG_UNSPEC", None),
	("NFTA_LOG_GROUP", NLA_U32),
	("NFTA_LOG_PREFIX", NLA_STRING),
	("NFTA_LOG_SNAPLEN", NLA_U32),
	("NFTA_LOG_QTHRESHOLD", NLA_U32),
	("NFTA_LOG_LEVEL", NLA_U32, nft_log_level),
	("NFTA_LOG_FLAGS", NLA_U32),
]

nft_queue_attributes = [
	("NFTA_QUEUE_UNSPEC", None),
	("NFTA_QUEUE_NUM", NLA_U16),
	("NFTA_QUEUE_TOTAL", NLA_U16),
	("NFTA_QUEUE_FLAGS", NLA_U16),
	("NFTA_QUEUE_SREG_QNUM", NLA_U32, nft_registers),
]

nft_quota_attributes = [
	("NFTA_QUOTA_UNSPEC", None),
	("NFTA_QUOTA_BYTES", NLA_U64), # guess
	("NFTA_QUOTA_FLAGS", NLA_U32),
	("NFTA_QUOTA_PAD", None),
	("NFTA_QUOTA_CONSUMED", NLA_U64),
]

nft_reject_attributes = [
	("NFTA_REJECT_UNSPEC", None),
	("NFTA_REJECT_TYPE", NLA_U32, nft_reject_types),
	("NFTA_REJECT_ICMP_CODE", NLA_U8),
]

nft_nat_attributes = [
	("NFTA_NAT_UNSPEC", None),
	("NFTA_NAT_TYPE", NLA_U32, nft_nat_types),
	("NFTA_NAT_FAMILY", NLA_U32),
	("NFTA_NAT_REG_ADDR_MIN", NLA_U32, nft_registers),
	("NFTA_NAT_REG_ADDR_MAX", NLA_U32, nft_registers),
	("NFTA_NAT_REG_PROTO_MIN", NLA_U32, nft_registers),
	("NFTA_NAT_REG_PROTO_MAX", NLA_U32, nft_registers),
	("NFTA_NAT_FLAGS", NLA_U32),
]

nft_exthdr_attributes = [
	("NFTA_EXTHDR_UNSPEC", None),
	("NFTA_EXTHDR_DREG", NLA_U32, nft_registers),
	("NFTA_EXTHDR_TYPE", NLA_U8),
	("NFTA_EXTHDR_OFFSET", NLA_U32),
	("NFTA_EXTHDR_LEN", NLA_U32),
	("NFTA_EXTHDR_FLAGS", NLA_U32),
	("NFTA_EXTHDR_OP", NLA_U32, nft_exthdr_op), # guess
	("NFTA_EXTHDR_SREG", NLA_U32),
]

nft_tproxy_attributes = [
	("NFTA_TPROXY_UNSPEC", None),
	("NFTA_TPROXY_FAMILY", NLA_U32), # guess
	("NFTA_TPROXY_REG_ADDR", None),
	("NFTA_TPROXY_REG_PORT", NLA_U32), # guess
]

nft_ng_attributes = [
	("NFTA_NG_UNSPEC", None),
	("NFTA_NG_DREG", NLA_U32),
	("NFTA_NG_MODULUS", NLA_U32),
	("NFTA_NG_TYPE", NLA_U32, nft_ng_types), # guess
	("NFTA_NG_OFFSET", NLA_U32),
	("NFTA_NG_SET_NAME", NLA_STRING),
	("NFTA_NG_SET_ID", NLA_U32),
]

nft_fib_attributes = [
	("NFTA_FIB_UNSPEC", None),
	("NFTA_FIB_DREG", NLA_U32),
	("NFTA_FIB_RESULT", NLA_U32, nft_fib_result), # guess
	("NFTA_FIB_FLAGS", NLA_U32),
]

nft_dup_attributes = [
	("NFTA_DUP_UNSPEC", None),
	("NFTA_DUP_SREG_ADDR", NLA_U32, nft_registers),
	("NFTA_DUP_SREG_DEV", NLA_U32, nft_registers),
]

nft_fwd_attributes = [
	("NFTA_FWD_UNSPEC", None),
	("NFTA_FWD_SREG_DEV", NLA_U32, nft_registers),
	("NFTA_FWD_SREG_ADDR", NLA_U32, nft_registers),
	("NFTA_FWD_NFPROTO", None),
]

nft_redir_attributes = [
	("NFTA_REDIR_UNSPEC", None),
	("NFTA_REDIR_REG_PROTO_MIN", NLA_U32, nft_registers),
	("NFTA_REDIR_REG_PROTO_MAX", NLA_U32, nft_registers),
	("NFTA_REDIR_FLAGS", NLA_U32),
]

nft_synproxy_attributes = [
	("NFTA_SYNPROXY_UNSPEC", None),
	("NFTA_SYNPROXY_MSS", NLA_U16),
	("NFTA_SYNPROXY_WSCALE", NLA_U8),
	("NFTA_SYNPROXY_FLAGS", NLA_U32),
	("__NFTA_SYNPROXY_MAX", None),
]

nft_devices_attributes = [
	("NFTA_DEVICE_UNSPEC", None),
	("NFTA_DEVICE_NAME", NLA_STRING),
]

def guess_nest_list(prev_val):
    if prev_val == "NFTA_EXPR_NAME=immediate":  return nft_immediate_attributes
    if prev_val == "NFTA_EXPR_NAME=payload":    return nft_payload_attributes
    if prev_val == "NFTA_EXPR_NAME=cmp":        return nft_cmp_attributes
    if prev_val == "NFTA_EXPR_NAME=lookup":     return nft_lookup_attributes
    if prev_val == "NFTA_EXPR_NAME=bitwise":    return nft_bitwise_attributes
    if prev_val == "NFTA_EXPR_NAME=meta":       return nft_meta_attributes
    if prev_val == "NFTA_EXPR_NAME=limit":      return nft_limit_attributes
    if prev_val == "NFTA_EXPR_NAME=connlimit":  return nft_connlimit_attributes
    if prev_val == "NFTA_EXPR_NAME=log":        return nft_log_attributes
    if prev_val == "NFTA_EXPR_NAME=queue":      return nft_queue_attributes
    if prev_val == "NFTA_EXPR_NAME=quota":      return nft_quota_attributes
    if prev_val == "NFTA_EXPR_NAME=reject":     return nft_reject_attributes
    if prev_val == "NFTA_EXPR_NAME=nat":        return nft_nat_attributes
    if prev_val == "NFTA_EXPR_NAME=exthdr":     return nft_exthdr_attributes
    if prev_val == "NFTA_EXPR_NAME=tproxy":     return nft_tproxy_attributes    # no test
    if prev_val == "NFTA_EXPR_NAME=numgen":     return nft_ng_attributes        # guess
    if prev_val == "NFTA_EXPR_NAME=fib":        return nft_fib_attributes       # no test
    if prev_val == "NFTA_EXPR_NAME=dup":        return nft_dup_attributes       # no test
    if prev_val == "NFTA_EXPR_NAME=fwd":        return nft_fwd_attributes       # no test
    if prev_val == "NFTA_EXPR_NAME=redirect":   return nft_redir_attributes     # no test
    if prev_val == "NFTA_EXPR_NAME=synproxy":   return nft_synproxy_attributes  # no test
    if prev_val == "NFTA_EXPR_NAME=device":     return nft_devices_attributes   # no test
    return None


# Message Types
nf_tables_msg_types = [
    ("NFT_MSG_NEWTABLE", nft_table_attributes),
    ("NFT_MSG_GETTABLE", nft_table_attributes),
    ("NFT_MSG_DELTABLE", nft_table_attributes),
    ("NFT_MSG_NEWCHAIN", nft_chain_attributes),
    ("NFT_MSG_GETCHAIN", nft_chain_attributes),
    ("NFT_MSG_DELCHAIN", nft_chain_attributes),
    ("NFT_MSG_NEWRULE", nft_rule_attributes),
    ("NFT_MSG_GETRULE", nft_rule_attributes),
    ("NFT_MSG_DELRULE", nft_rule_attributes),
    ("NFT_MSG_NEWSET", nft_set_attributes),
    ("NFT_MSG_GETSET", nft_set_attributes),
    ("NFT_MSG_DELSET", nft_set_attributes),
    ("NFT_MSG_NEWSETELEM", nft_set_elem_list_attributes), # guess
    ("NFT_MSG_GETSETELEM", nft_set_elem_list_attributes), # guess
    ("NFT_MSG_DELSETELEM", nft_set_elem_list_attributes), # guess
    ("NFT_MSG_NEWGEN", nft_gen_attributes),
    ("NFT_MSG_GETGEN", nft_gen_attributes),
    ("NFT_MSG_TRACE", nft_trace_attributes),
    ("NFT_MSG_NEWOBJ", nft_object_attributes), # guess
    ("NFT_MSG_GETOBJ", nft_object_attributes), # guess
    ("NFT_MSG_DELOBJ", nft_object_attributes), # guess
    ("NFT_MSG_GETOBJ_RESET", nft_object_attributes), # guess
    ("NFT_MSG_NEWFLOWTABLE", nft_flowtable_attributes),
    ("NFT_MSG_GETFLOWTABLE", nft_flowtable_attributes),
    ("NFT_MSG_DELFLOWTABLE", nft_flowtable_attributes),
]

def ceil(n, m=4):
    return (n - 1) + (m - (n - 1) % m)

class Netlink:
    def __init__(self, data):
        self.nlmsg_len   = u32(data[:4])
        self.nlmsg_type  = u8(data[4:5])
        self.nlmsg_flags = u16(data[6:8])
        self.nlmsg_seq   = u32(data[8:12])
        self.nlmsg_pid   = u32(data[12:16])
        self.payload     = data[16:self.nlmsg_len]

class Netfilter:
    def __init__(self, data):
        self.nfgen_family = u8b(data[:1])
        self.version      = u8b(data[1:2])
        self.res_id       = u16b(data[2:4])
        self.payload      = data[4:]

class Attribute:
    def __init__(self, data):
        self.nla_len  = u16(data[:2])
        self.nla_type = u16(data[2:4])
        self.payload  = data[4:self.nla_len]

def parse_packet(packet):
    packet_family   = u16b(packet[:2])
    netlink_packet  = packet[2:]

    if packet_family != 0x0C:
        print("packet_family != 0x0C (Not Netfilter)")
        return

    for nl in split_netlink(netlink_packet):
        attr_name, types_list = nf_tables_msg_types[nl.nlmsg_type]
        nf = Netfilter(nl.payload)

        print(f"{attr_name}, family: {SA_FAMILY[nf.nfgen_family]}, version: {nf.version}, resource-id: {nf.res_id}")

        unmarshal_attribute(nf.payload, types_list)

def split_netlink(data):
    result = []

    while len(data) > 0:
        nl = Netlink(data)

        result.append(nl)
        data = data[ceil(nl.nlmsg_len):]

    return result

def unmarshal_attribute(data, types_list, depth=1):
    indent = "    " * depth
    last_result = None

    def next_attr(data, attr):
        return data[ceil(attr.nla_len):]

    def guess_nest(data, attr_type):
        if len(data) >= 4:
            if attr_type == NLA_NESTED:
                return True

            nla_len  = u16(data[:2])
            nla_type = u16(data[2:4])

            if 0 < nla_len <= len(data):
                if nla_type < 64:
                    return True

        return False

    while len(data) >= 4:
        attr = Attribute(data)
        data = next_attr(data, attr)

        nest_list = None
        const_list = None

        if types_list:
            tmp = types_list[attr.nla_type]
            attr_name = tmp[0]
            attr_type = tmp[1]

            if attr_type == NLA_NESTED:
                nest_list = tmp[2]
            elif attr_type in [NLA_U8, NLA_U16, NLA_U32, NLA_U64]:
                const_list = tmp[2] if len(tmp) == 3 else None

        else:
            attr_name = f"type {attr.nla_type}"
            attr_type = None

        if (guess_nest(attr.payload, attr_type)):
            # ad hoc method
            if not nest_list:
                x = guess_nest_list(last_result)
                nest_list = x if x else None

            print(indent + f"- {attr_name}")
            unmarshal_attribute(attr.payload, nest_list, depth + 1)
        else:
            if   attr_type == NLA_U8:  attr.payload = u8b(attr.payload)
            elif attr_type == NLA_U16: attr.payload = u16b(attr.payload)
            elif attr_type == NLA_U32: attr.payload = u32b(attr.payload)
            elif attr_type == NLA_U64: attr.payload = u64b(attr.payload)
            elif attr_type in [NLA_STRING, NLA_NUL_STRING]:
                attr.payload = attr.payload[:-1].decode() if attr.payload[-1] == 0 else attr.payload
                last_result = f"{attr_name}={attr.payload}"

            if attr_type in [NLA_U8, NLA_U16, NLA_U32, NLA_U64]:
                if const_list:
                    attr.payload = const_list[attr.payload]
                else:
                    attr.payload = hex(attr.payload)

            print(indent + f"+ {attr_name}: {attr.payload} (len={attr.nla_len-4})")


def main(filename):
    pcap_data = dpkt.pcap.Reader(open(filename, "rb"))

    for packet_no, (time, packet) in enumerate(pcap_data):
        print(f"\n[#{packet_no}]")
        packet = dpkt.ethernet.Ethernet(packet).data
        parse_packet(packet)

if len(sys.argv) == 2:
    main(sys.argv[1])
else:
    #main("easynft.pcap")
    main("nft.pcap")
    #main("sample.pcap")



