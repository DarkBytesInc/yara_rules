rule Win_Trojan_Dumador_64
{
strings:
	$a0 = { 0aebccc8040000bb47414c46ff7514ff75 }
	$a1 = { 6f75743a626c000000000053796d626f6c2073657175656e63653a0d000d0d5d5c6476702e6c6f670057494e49 }

condition:
	$a0 and $a1
}

        
