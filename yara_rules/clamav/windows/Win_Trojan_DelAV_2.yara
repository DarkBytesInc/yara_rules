rule Win_Trojan_DelAV_2
{
strings:
	$a0 = { 64656c20633a5c64727765625c2a2e3f3f3f200d0a64656c20633a5c6176705c2a2e3f3f3f200d0a64656c20633a5c7363616e5c2a2e3f3f3f }

condition:
	$a0
}

        
