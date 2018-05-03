rule Win_Worm_Stuxnet_12
{
strings:
	$a0 = { 8bff558bec837d0c017505e8a60300005de99bfdffffff25ac00021080f940731580f92073060fa5c2d3e0 }

condition:
	$a0
}

        
