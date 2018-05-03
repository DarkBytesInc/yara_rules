rule Win_Trojan_Packed_146
{
strings:
	$a0 = { 03d103d103d103d103d103d103d103d1 }

condition:
	$a0
}

        
