rule Win_Trojan_Spambot_141
{
strings:
	$a0 = { ff1072d54d6e05b053ec09bfffa666c1aacdfefffdffb3cc660e4ff75ec6d7eb8a537773f9883c2323d68a9421b2996895e4ff7ffa0f558e73fbed11e322f96addf80f3fd199a42687e3caffffffffb63bf4fa6f7093868f56ae4c48e19b3642ac7caeb54f75b0ef9fa5891e66f6 }

condition:
	$a0
}

        
