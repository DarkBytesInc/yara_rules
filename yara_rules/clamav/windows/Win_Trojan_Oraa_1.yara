rule Win_Trojan_Oraa_1
{
strings:
	$a0 = { 476d45733d6563686f0d0a254f5261476d45732520dbdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdb0d0a254f5261476d45732520db204f526147206279204d6944655a205b526930546552535d20db0d0a254f5261476d45732520dbdcdcdcdcdcdcdcdcdc }

condition:
	$a0
}

        
