rule Win_Trojan_Bifrose_702
{
strings:
	$a0 = { e2f200285ff0ea3453d0c803e98592c0b65be8f7d787000efb83e1cd65c30100b84ca6883fd2f4700098a9975e21f9fa1a0194c82f2241d6d8d4509300e49685f2afb551 }

condition:
	$a0
}

        
