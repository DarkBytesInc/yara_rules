rule Win_Trojan_CVE_2010_3333_4
{
strings:
	$a0 = { 7b5c727466 }
	$a1 = { 5c736870 }
	$a2 = { 5c7370 }
	$a3 = { 7b5c737620363b0d0a0d0a617361616161616161610d0a61616161616161616161 }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
