rule Win_Downloader_Banload_268
{
strings:
	$a0 = { 910522ee38a2ba854a89ba4e06fbf2b15ad566519c87ba543a030ca226d7540a289ebd27d5df081ae6704a9dc9411364df8cabd4759afde6fe11b0ee83b5701a835922f07817f91ad98f7ae3d338fe4402db7e034d70afa8f3f8 }

condition:
	$a0
}

        
