rule Win_Trojan_VB_1077
{
strings:
	$a0 = { 2d00730074006100720074[0-19]68006b002e006500780065 }
	$a1 = { 69006f006e005c00520075006e }

condition:
	$a0 and $a1
}

        
