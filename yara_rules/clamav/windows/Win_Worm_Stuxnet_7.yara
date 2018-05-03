rule Win_Worm_Stuxnet_7
{
strings:
	$a0 = { 8b44240883e800742248751fff742404ff153c300010e86b01000085c0740cff }

condition:
	$a0
}

        
