rule Win_Trojan_KillAV_34
{
strings:
	$a0 = { 6e657874202573797374656d726f6f74252f74656d702f64617869616e332e302e657865 }

condition:
	$a0
}

        
