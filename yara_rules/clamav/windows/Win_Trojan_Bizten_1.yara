rule Win_Trojan_Bizten_1
{
strings:
	$a0 = { 50e8e5f3ffff4383fb0575c0eb0c56e81ff4ffff56e8e9f3ffff6a006a006a0056e8e5f3ffff85c075e433c05a5959648910686c474000c3e92ae7ffffebf85f5e5be894ebffff57696e4d696e203a204d61696e00000057696e204d696e00433a5c446f63 }

condition:
	$a0
}

        