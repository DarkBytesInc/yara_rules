rule Win_Trojan_Trivial_366
{
strings:
	$a0 = { 0161b44e33c9ba4901cd217239b8023dba9e00cd2193b43fb90400ba4f01cd21803e5201617508b43ecd21b44febd532c0b44233c999cd21b440b95300ba0001cd21 }

condition:
	$a0
}

        
