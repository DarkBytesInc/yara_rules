rule Win_Trojan_Bancos_958
{
strings:
	$a0 = { eeef2e748c9545d3c8456e512b14e2fa2212ab68ae351b32f3bda92ed4e8d2d09a40d67fc519020bda34eec4adf065193c0da99b2b69547c308804a20f253c26457193a51c7b2013ea484d0ae3abfb0aefcffd7cb5f08f46 }

condition:
	$a0
}

        
