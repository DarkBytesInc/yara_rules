rule Win_Trojan_Nibble_1
{
strings:
	$a0 = { 433a5c746573742e7a6970[0-144]5c43757272656e7456657273696f6e5c52756e[0-1]5c736430776e2e657865 }

condition:
	$a0
}

        
