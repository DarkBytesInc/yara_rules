rule Win_Trojan_VGEN_63
{
strings:
	$a0 = { 06e800005d81edc902b82120cd2181f92120743d8cc0488ed833f6803c5a7531816c033500816c1235008b44128ec08e }

condition:
	$a0
}

        
