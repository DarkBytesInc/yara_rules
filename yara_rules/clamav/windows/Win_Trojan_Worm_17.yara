rule Win_Trojan_Worm_17
{
strings:
	$a0 = { e8d520000083f8ff7525ff7508e8bc2000000bc07507b8ffffffffeb128b400c0bc07507b8ffffffffeb048b008b00c9c20400558bec81c4f4feffffff750c8f85f4feffffc785f8feffff00000000c785fcfeffff010000008d8500ffffffff75088f008d85f4feffff506a006a008d }

condition:
	$a0
}

        
