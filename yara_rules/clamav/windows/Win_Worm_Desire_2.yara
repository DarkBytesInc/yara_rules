rule Win_Worm_Desire_2
{
strings:
	$a0 = { 2f2e636f7079202d6f20[0-10]5c6261636b75702e70696620633a5c6465736972652e657865 }

condition:
	$a0
}

        
