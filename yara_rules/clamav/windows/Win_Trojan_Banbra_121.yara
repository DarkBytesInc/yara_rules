rule Win_Trojan_Banbra_121
{
strings:
	$a0 = { 653819ac3cd7973bf1acc4e2e916688254b2dc880453e146dc459f649d7137e7bcfb00e8099b5c04c965d7e4705c3545dc2dd5352a724d8cb522bfb76cf4d1a0fbca6cbc2da985e0321d9f3bda9434ab8a4f8732ac4c8fb141f14fbd9853dc6ff3435cf7731b4b1cdd8340885c09 }

condition:
	$a0
}

        