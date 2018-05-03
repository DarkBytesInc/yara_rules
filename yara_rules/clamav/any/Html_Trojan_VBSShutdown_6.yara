rule Html_Trojan_VBSShutdown_6
{
strings:
	$a0 = { 2e72756e2022636d642e657865202f632073687574646f776e202d72202d74203235202d63 }

condition:
	$a0
}

        
