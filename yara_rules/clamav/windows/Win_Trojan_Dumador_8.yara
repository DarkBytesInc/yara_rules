rule Win_Trojan_Dumador_8
{
strings:
	$a0 = { d25786c60faffa0fbdd8156adcf9b12d6b7c26d90fbfd0c1c22c0fafdbf38af7f7c2cb2be802460fc0fc0fb3db0fbcfbbb6562b32abb320a264a0facd0e6f2c6c641d0cbc6c66ebfd7b23f9884c30fa4df978d15cdb4b5e4e2908d1d1422389c0fafc386e064b3f5f7c77d41d1223e01 }

condition:
	$a0
}

        
