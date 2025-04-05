struct tx_tstamp_event {
	__u32 type;
	__u32 id;
	__u64 nsec;
};

#define SOL_CUSTOM_TESTER	0x89abcdef
