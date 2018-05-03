rule Unix_Trojan_BDFactory_5
{
strings:
	$a0 = { 0040a0e1000040e00270a0e3000000ef000050e30400a0e1044044e00070a0e30000000a[20-24]000000ef }

condition:
	$a0
}

        
