rule Win_Worm_Stuxnet_15
{
strings:
	$a0 = { 807c2408010f85d00b000060be000010108dbe0010f0ff5789e58d9c2480c1ffff31c05039dc75fb464653686deb18 }

condition:
	$a0
}

        
