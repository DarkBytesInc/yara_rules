rule Win_Trojan_Agent_34924
{
strings:
	$a0 = { 8eeb0d98bf9b2b02ad8fa498f2a42d92dd902a8fdbb73e91bed477af82b776dd9a91332b6b5aea8dfbd7688a94c23cdc5789440bbb8026c2f4ba0caefbeb649c099b00a28dd70092b59dd04bb13505f2c0832c8ec59f8452af2f }

condition:
	$a0
}

        
