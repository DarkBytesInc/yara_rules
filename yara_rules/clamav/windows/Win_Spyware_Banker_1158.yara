rule Win_Spyware_Banker_1158
{
strings:
	$a0 = { b1201f30422d3a98333aa48ee0d1ffff5e424d8b994fa44ccb01caee75077e4e9c34bbfb11ffff2f4011146503dd9676a7f4bfc83c832dca32b53226ffffffff24c94c72b430f6500189beaa7164cbb48fa8318381357df531a4 }

condition:
	$a0
}

        
