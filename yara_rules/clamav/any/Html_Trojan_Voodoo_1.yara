rule Html_Trojan_Voodoo_1
{
strings:
	$a0 = { 6966206936693267323d223c212d2d48544d4c2e4275726e745f50617065725f446f6c6c2d2d3e22207468656e }

condition:
	$a0
}

        
