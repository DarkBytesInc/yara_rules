rule Win_Trojan_F_41
{
strings:
	$a0 = { 28666f756e645f66696c652c222e66652229[0-67]286d795f636f646529[0-2]696e66656374696f6e732b2b3b }

condition:
	$a0
}

        
