rule Win_Trojan_Gen_242
{
strings:
	$a0 = { ff7503e9300250e8070e5989160531a303310bd27c0d7f053d32177606c70668020100 }

condition:
	$a0
}

        
