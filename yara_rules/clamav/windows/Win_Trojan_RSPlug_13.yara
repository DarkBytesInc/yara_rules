rule Win_Trojan_RSPlug_13
{
strings:
	$a0 = { 24726573203d7e2074727c60202d5f7c61612d7a612d7a302d392b2f7c3b }
	$a1 = { 6d792024756e697169[0-16]226d61633b222e24636d6429 }

condition:
	$a0 and $a1
}

        
