rule Win_Trojan_VB_1040
{
strings:
	$a0 = { 6840174000e8eeffffff00000000000030 }
	$a1 = { 61657365 }
	$a2 = { 676164666473676164736673667330313633334234414438 }

condition:
	$a0 and $a1 and $a2
}

        
