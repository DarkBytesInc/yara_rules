rule Win_Trojan_BIZATCA_1
{
strings:
	$a0 = { e8000000005d8bc52d050003005081ed050044008b85af03440081389cfc5053750f909090908b85 }

condition:
	$a0
}

        
