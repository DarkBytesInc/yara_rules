rule Win_Trojan_Java_97
{
strings:
	$a0 = { 687474703a2f2f64696e65742e696e666f2f6367692d62696e2f696e702e706c3f6869706f696e746e616d653d }

condition:
	$a0
}

        
