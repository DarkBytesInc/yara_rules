rule Win_Trojan_Bifrose_157
{
strings:
	$a0 = { 8206d2f8f7e7dc1f9c58105ff4dd9840e96a2a2d13163f4090800ad4551428debd710c00b823c6e1e9eeb9aa00ce57b16cf160d38200bd76634518ebb76200121f960510 }

condition:
	$a0
}

        
