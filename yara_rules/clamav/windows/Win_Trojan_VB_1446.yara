rule Win_Trojan_VB_1446
{
strings:
	$a0 = { ec144000000000000000000000000000ec14400000000000??????0001000500fc18400000000000ffffffffffffffff00000000401a400058504000020000002c1540000000000000000000000000002c154000??????????????0001000400fc18400000000000ffffffffffffffff00000000101a4000385040000a000000701540000100200000000000????1a006c154000??204000750061006c002000530074007500640069006f005c0056004200390038005c00430032002e00450056423521f01f7662366368732e646c6c000000002a000000000000000000000000000a000408000000000000f02a4000c016400000f0300000ffffff080000000100000000000000e9000000f8134000f8134000bc13400078000000810000008700000088000000000000000000000000000000000000003031 }

condition:
	$a0
}

        