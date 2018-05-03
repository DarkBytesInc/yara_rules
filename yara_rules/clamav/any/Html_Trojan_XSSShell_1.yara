rule Html_Trojan_XSSShell_1
{
strings:
	$a0 = { 787373207368656c6c[0-100]666572727568206d61766974756e61 }

condition:
	$a0
}

        
