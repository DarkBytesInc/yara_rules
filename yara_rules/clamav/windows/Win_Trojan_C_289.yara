rule Win_Trojan_C_289
{
strings:
	$a0 = { 28636d642c272f632072656e[0-17]2a2e6d703327293b[0-13]2a2e6d7033272c2433462c76696374696d29 }

condition:
	$a0
}

        
