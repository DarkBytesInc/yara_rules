rule Win_Trojan_Lineage_201
{
strings:
	$a0 = { ec09c6805f3c0f0483cf63db67203582d7afe91e21198a1b0f5ae0ac5de694ddb86a9ccabdab3b39614f65c4eaad860b1d0fa64de1c80dc43dcff100f53e0668928a2bff2ca65cfa6cc947e05ca58afdc192f6a4d848127eae64ab3011c4d1f1f6bbeedb3d2d33465bbdea682baf4af6ce3748908fe3f31c9d966ca28215cbac }

condition:
	$a0
}

        
