rule Win_Trojan_StartPage_36
{
strings:
	$a0 = { 2f2f7368646f6370652e646c6c }
	$a1 = { 53746172742050616765 }
	$a2 = { 5c4d6963726f736f66745c496e7465726e6574204578706c6f7265725c4d61696e }

condition:
	$a0 and $a1 and $a2
}

        
