rule Win_Trojan_Spambot_259
{
strings:
	$a0 = { ee41ec091cf6fe48010d6c4907ffffffffc20d83a45dfef6896867ff7cc1d8aab87a92deb6687156358725a31bf0d44b5fffffffff20e4354984761e28bfd28c7f86224609494fd4f8161f806d0c798c7b22b7dec1ffa7ffff28732a0b94c8338d3d52a860e3ea8d2d90b58a0aab }

condition:
	$a0
}

        
