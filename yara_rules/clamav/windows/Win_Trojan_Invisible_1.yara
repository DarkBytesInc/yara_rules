rule Win_Trojan_Invisible_1
{
strings:
	$a0 = { bbe3347500b9586016177900baec0b0400565e81c1c6aaeb007f007300309781cc06077200437b0000f2f5f575007400e2eb }

condition:
	$a0
}

        
