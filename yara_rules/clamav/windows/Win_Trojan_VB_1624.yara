rule Win_Trojan_VB_1624
{
strings:
	$a0 = { 7468656c69756d00000000bc69640200f763020000000000000000b0 }

condition:
	$a0
}

        
