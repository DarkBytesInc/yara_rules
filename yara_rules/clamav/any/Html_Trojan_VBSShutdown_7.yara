rule Html_Trojan_VBSShutdown_7
{
strings:
	$a0 = { 7773687368656c6c612e72756e2022636d642e657865202f632073687574646f776e202d72 }

condition:
	$a0
}

        
