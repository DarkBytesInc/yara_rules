rule Win_Trojan_Sturbax_1
{
strings:
	$a0 = { 737461722e6265616e732e70726f706572747976616c7565[0-84]6d6163726f3a2f2f[0-174]6f6e6c6f6164 }

condition:
	$a0
}

        
