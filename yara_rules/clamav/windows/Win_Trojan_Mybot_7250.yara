rule Win_Trojan_Mybot_7250
{
strings:
	$a0 = { b68b83a424a76e14f4dd932a8591f8010982dffa383287ecaafcb84fcf4b75cf42e89724b4bced0ae4798128f5779b6cc7533100d40a5a8d5ba6127a5eadbda2db60962c03e66f16244432427730 }

condition:
	$a0
}

        
