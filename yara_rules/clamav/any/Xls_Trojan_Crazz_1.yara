rule Xls_Trojan_Crazz_1
{
strings:
	$a0 = { 647461283229203d20226e323d202f6463632073656e6420246e69636b20433a5c77696e646f77735c4e6f74326f70656e2e786c7322 }

condition:
	$a0
}

        