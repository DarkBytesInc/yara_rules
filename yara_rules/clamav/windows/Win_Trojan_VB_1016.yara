rule Win_Trojan_VB_1016
{
strings:
	$a0 = { 5c006b0064006900750065003700330032002e007400780074 }

condition:
	$a0
}

        
