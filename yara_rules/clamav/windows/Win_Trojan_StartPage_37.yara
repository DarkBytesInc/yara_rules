rule Win_Trojan_StartPage_37
{
strings:
	$a0 = { 5c4d6963726f736f66745c496e7465726e6574204578706c6f7265725c4d61696e }
	$a1 = { 79616e6465782e386d2e636f6d }
	$a2 = { 53746172742050616765 }

condition:
	$a0 and $a1 and $a2
}

        
