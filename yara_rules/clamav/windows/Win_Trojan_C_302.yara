rule Win_Trojan_C_302
{
strings:
	$a0 = { 61005c004d006100630072006f002e006500780065 }
	$a1 = { 4c007500630069006600650072 }

condition:
	$a0 and $a1
}

        
