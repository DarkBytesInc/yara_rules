rule Unix_Trojan_Shellcode_26
{
strings:
	$a0 = { e83f1ffd08210280340201020841040260400162b45a01540b3902990b180298341604be }

condition:
	$a0
}

        
