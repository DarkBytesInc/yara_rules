rule Win_Trojan_Hello_6
{
strings:
	$a0 = { 9a00001e019a0d00bc005589e5b800019acd021e0181ec0001c606700000c606d25400c606d35400c606d45400b00050 }

condition:
	$a0
}

        
