rule Win_Spyware_Banker_3338
{
strings:
	$a0 = { b1155b4928e31c9297b2dbb8726a5b48d4ad98d16c934a5c693226f40afa682bfb53f27c77d2b0044591ad989c1cb432836c01a0ad525138859cd6c9370cd6b50fea227d513f }

condition:
	$a0
}

        
