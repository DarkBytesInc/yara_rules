rule Win_Trojan_QQPass_48
{
strings:
	$a0 = { 6a008d45e8e899f5ffff8d45e8bacc4f4000e884eaffff8b45e8e8d0ebffff508d55e433c0e8ddd9ffff8b45e4e8bdebffff50e843f1ffff68d44f40006a006801001f00e8eaf1ffff85c0751568e44f40006a006801001f00 }

condition:
	$a0
}

        
