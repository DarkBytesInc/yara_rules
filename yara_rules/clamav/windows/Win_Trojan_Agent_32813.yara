rule Win_Trojan_Agent_32813
{
strings:
	$a0 = { 9c589a98404f03958ce8f55f7f91624dbfac904a0297b9b8c0b496d6401835ba02c0158ac02a31f2c3fa843ce4970a29b01341167e50f4a54d4b2ca76e64a71e70 }

condition:
	$a0
}

        
