rule Win_Trojan_VB_1495
{
strings:
	$a0 = { 742f400007000000082f400007000000c82e400007000000782e400007000000302e400001000000f42c400000000000ffffffffffffffff00000000482d400008a04000050000000418400000000000000000000000000004184000000000000000000000000000000000000000000050000000c80706e86e1342458d6292b2e7071d1b0000000000000000000000000000000001000000800b000000000000000000000000000000000000000000004417000000000000fc3840004c0000005642352136262a000000000000000000000000007e000000000000000000000000000a00090400000000000050514000f418400000f0380000ffffff080000000100000001000500e900000018184000301b400060174000780000007d0000008400000085000000000000000000000000000000000000006a756c79006172636869650000??????????0000f4010000f42c40000000000040514000d08e4000180b000008a04000c614400000a040000000000000000000000000000000000000000000000000000000000000000000 }

condition:
	$a0
}

        