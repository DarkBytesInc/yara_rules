rule Win_Trojan_Fakeav_37
{
strings:
	$a0 = { 83ec18e83d000000e8240000005983c404585aff8ab0000000750a8182b800000072000000525052 }

condition:
	$a0
}

        
