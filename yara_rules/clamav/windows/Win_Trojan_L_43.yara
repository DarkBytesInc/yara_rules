rule Win_Trojan_L_43
{
strings:
	$a0 = { ceffff83c41085c00f8c730100006a00e8dbf8ffff8d04808d04c5390e0000b9d902000099f7f98995d0ceffff83c4048d9500e0ffff8995ccceffff68002000008b8dccceffff518b95e0ceffff52e841f9ffff8985dcceffff83c40c85c00f8e080100008b8dccceffff898d }

condition:
	$a0
}

        
