rule Win_Trojan_VB_5744782_0
{
strings:
	$a0 = { f80004040c002800000000002800040438001003000005009001043404000a2075000400010106020a2062000501810008030b20020086010a030b20020088010c030b2004008c010c000400000000000400040416002408000001002404043424000a2075002400000400000c000c00000000000c0004040c001000000000001000040414002800000002002800042c20000100240001000c001c00000000001c0004041600180000000100100004340800 }

condition:
	$a0
}

        