rule Win_Trojan_Autorun_335
{
strings:
	$a0 = { 636f7079206175746f72756e2e696e6620693a0d0a64656c20633a2f77696e646f77732f202a2e657865 }

condition:
	$a0
}

        
