rule Win_Trojan_Philis_58
{
strings:
	$a0 = { 506a00e831feffff8d45e48bd3e8bbf5ffff8b45e433d2e8a1feffff33db33c05a595964891068d33c40008d45e4ba07000000e899f4ffffc3e983eeffffebeb8bc35b8be55dc20400ffffffffa0000000687474703a2f2f7777772e7477 }

condition:
	$a0
}

        
