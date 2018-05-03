rule Php_Trojan_CryptoPHP_1
{
strings:
	$a0 = { 3c3f70687020696e636c756465202827696d616765732f736f6369616c2e706e6727293b203f3e }

condition:
	$a0
}

        
