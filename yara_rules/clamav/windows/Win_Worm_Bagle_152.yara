rule Win_Worm_Bagle_152
{
strings:
	$a0 = { 863808f91e7b77d8a6b1362f637275cd403b7825c710680a06addaee62bb0df48fcdcf5a344683ab08673f78ad17240bce1665a7d675fc4c8a263a5a8facf68be45b423ffcb80e5f4c24e275dac94482 }

condition:
	$a0
}

        
