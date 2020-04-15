package common

type RxTxDriver uint

const (
	UNKNOWN RxTxDriver = iota
	DPDK
	AF_PACKET
)
