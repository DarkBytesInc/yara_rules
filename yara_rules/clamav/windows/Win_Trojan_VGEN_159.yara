rule Win_Trojan_VGEN_159
{
strings:
	$a0 = { e800005d81ed0601eb00e81d00eb2e2ec7862b013000e81100b99a028d960301b440cd21e80300c300002e8b862b018d }

condition:
	$a0
}

        
