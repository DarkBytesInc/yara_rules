rule Win_Trojan_Backserv_1
{
strings:
	$a0 = { 83c4fc6a108d8530ffffff508b8548ffffff50e841fdffff83c41089c083f8ff751d83c4f468f18a0408e8bafcffff83c41083c4f46affe83dfdffff83c41083c4f86a058b8548ffffff50e8d9fcffff83c41089c083f8ff751f83c4f468f68a0408e882fcffff83c41083c4f46affe805fdffff83c41089f6 }
	$a1 = { 20494f43202d1b5b306d0a1b5b313b33376d4372656174696e67202f2e72686f737473202e2e2e1b5b306d0a1b5b313b33316d4f4b2c }

condition:
	$a0 and $a1
}

        