rule Win_Trojan_Laroux_66
{
strings:
	$a0 = { 6d616a6f6475636b2020d4002400800101002500e00001002800ea0046006000ffff6700ffffad0000002000400028004a00ae04200040002800c0000000ad001600746d707379732e786c7321636865636b5f66696c65732000400028004a0040004f00ffff20002a0121 }

condition:
	$a0
}

        