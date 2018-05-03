rule Osx_Trojan_SMSsend_1
{
strings:
	$a0 = { 706179666f726d2e706870 }
	$a1 = { 534d5320666f722061637469766174696f6e }
	$a2 = { 6f6b616c7920646f6b616c79 }
	$a3 = { 7468616e6b20796f75[0-5]616275736521 }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
