rule Win_Trojan_IM_150
{
strings:
	$a0 = { c745fc000000008b4508ff450880380074078d45fcff00ebee8b45fcc9c3 }
	$a1 = { 47657450726f634164647265737300 }
	$a2 = { 4c6f61644c6962726172794100 }

condition:
	$a0 and $a1 and $a2
}

        
