rule Win_Worm_Zaka_3
{
strings:
	$a0 = { 154000d418400000f0340000ffffff080000000100000001000000e900000084114000841140004011400078000000820000008c0000008d000000000000000000000000000000000000004c4144594469616e61004c4144594469616e61000050726f6a65637431000000070000000824400007000000b82340000700000060234000070000000c23400007000000 }

condition:
	$a0
}

        