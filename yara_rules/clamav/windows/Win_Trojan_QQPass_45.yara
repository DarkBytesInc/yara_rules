rule Win_Trojan_QQPass_45
{
strings:
	$a0 = { 6a008d45e8e859f5ffff8d45e8bab84f4000e898eaffff8b45e8e8e4ebffff508d55e433c0e8f1d9ffff8b45e4e8d1ebffff50e857f1ffff68c04f40006a006801001f00e8fef1ffff85c0751568d04f40006a006801001f00e8e9f1ffff85c0740a }

condition:
	$a0
}

        
