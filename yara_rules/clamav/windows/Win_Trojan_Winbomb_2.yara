rule Win_Trojan_Winbomb_2
{
strings:
	$a0 = { 766172636f756e743d31303030[0-30]6e742e6f70656e28226b696c6c2e68746d222c22222c222229 }

condition:
	$a0
}

        
