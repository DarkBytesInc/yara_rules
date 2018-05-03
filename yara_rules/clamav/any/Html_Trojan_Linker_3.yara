rule Html_Trojan_Linker_3
{
strings:
	$a0 = { 7372633d687474703a2f2f[0-14]2f68656c702e617370 }
	$a1 = { 633d687474703a2f2f73312e6361776a622e636f6d2f6a702e6a73 }

condition:
	$a0 and $a1
}

        
