rule Win_Trojan_Goodcom_1
{
strings:
	$a0 = { 636f7079202525325c253020256464255c203e20256464255c25626e252e626174 }
	$a1 = { 64656c20762e363636 }

condition:
	$a0 and $a1
}

        
