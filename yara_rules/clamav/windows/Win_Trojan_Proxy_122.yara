rule Win_Trojan_Proxy_122
{
strings:
	$a0 = { 467a686863732e646c6c004369736568614c6900527972616e79706977757861 }

condition:
	$a0
}

        
