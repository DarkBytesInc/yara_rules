rule Win_Trojan_Bancos_966
{
strings:
	$a0 = { 1e9e13ae2c80497535435ea955b5f7bf055dc1e47b382c95149904aebd193bb43ca8e1e355d633046d5f33ad158a789d3a159585f53a06a99408ec26398ab1b4afbff17fa296e2bd6b238f9fb828 }

condition:
	$a0
}

        
