rule Win_Trojan_Bancos_900
{
strings:
	$a0 = { faee9cb5737dd4340db2f4440915e61ed0a4c6fc6071a03147a2516c8de7de6b03fce275d05179df7d37348efda533f2818c5e82b200b0dd76ac229517f21a611dcd5a46408e57f1632a2fb35793 }

condition:
	$a0
}

        
