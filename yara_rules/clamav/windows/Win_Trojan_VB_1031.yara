rule Win_Trojan_VB_1031
{
strings:
	$a0 = { 796f757269006d65757575000050726f6a65637431 }
	$a1 = { 63003a005c004e0054002e006500780065 }

condition:
	$a0 and $a1
}

        
