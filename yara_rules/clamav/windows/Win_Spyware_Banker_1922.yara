rule Win_Spyware_Banker_1922
{
strings:
	$a0 = { 76f60f4a1db25c7ab2ef8ba5304b4d74713236ef43473055d8ac36859fde2414c3b751dc5899f2f7ecf8da4d471a1630de43a80d7bd58cebdb7509cb1d49d0592de34a2d92d2b57bec6d498c4fa64a0d4f34e25c91ab8038dffc2e323ddebd6cd1b39cb876200ef28bf855aeb5108ebfbff08d4ffc }

condition:
	$a0
}

        
