rule Win_Trojan_VB_1043
{
strings:
	$a0 = { 45787465726d696e61746f72 }
	$a1 = { 43003a005c006a007500730074002d006d0065002e007400780074 }

condition:
	$a0 and $a1
}

        
