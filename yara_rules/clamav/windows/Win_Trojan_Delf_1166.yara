rule Win_Trojan_Delf_1166
{
strings:
	$a0 = { 8bf085f60f8e91000000b90200000033d28bc6e85cffffff8bd081ea0001000033c98bc6e84bffffff8d95dcfeffffb9ff0000008bc6e845ddffff85c07e56b820774000e88bc6ffffc745f0010000008b45f08a9c05dcfeffff84db }

condition:
	$a0
}

        
