rule Win_Trojan_Small_4112
{
strings:
	$a0 = { 6a046a006a0068fffffbffff156cb0460085c07e086a00ff1558b04600a14896460031054096460031053c96460033c9 }

condition:
	$a0
}

        
