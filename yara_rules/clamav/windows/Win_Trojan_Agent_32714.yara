rule Win_Trojan_Agent_32714
{
strings:
	$a0 = { 7374bc3094b6d26707e096036d7a1e3c6c34719d85c13febb39385af1eac6a172933e4e88da77a18e96a91de9400f09471b4288ea15000b9010d5215 }

condition:
	$a0
}

        
