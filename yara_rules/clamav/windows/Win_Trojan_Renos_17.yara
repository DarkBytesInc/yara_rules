rule Win_Trojan_Renos_17
{
strings:
	$a0 = { 68feffff81e9d400000081c1af00000041219594feffffff8598feffff1995a8fdffff394dac723349098ddcfdffffbabd0f000029ca339524ffffff139590feffff41118d10feffff218df8feffff039530ffffff3395c8feffff039590fdffffb88304 }

condition:
	$a0
}

        
