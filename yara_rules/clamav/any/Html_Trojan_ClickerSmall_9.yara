rule Html_Trojan_ClickerSmall_9
{
strings:
	$a0 = { c0da525d624e5b702e0df66d792d69242e53666fd66a1381136bb9363b630d10c66f27737c62a7085b72043b685f6d69b6af08f97261636c656575705c63fc7fdbee }

condition:
	$a0
}

        
