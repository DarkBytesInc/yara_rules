rule Win_Trojan_Mybot_8504
{
strings:
	$a0 = { dfe3f500f980160b2ed03c72550dcfe175cec5bfba8e9559fe2282713231fab5ec0c97cdd9f038aedc71783bf8ca7b97028357ef154ef4a7a16411c098e338a306bae212f8e3e3a9b7b10d94431494e3443bd44f95 }

condition:
	$a0
}

        
