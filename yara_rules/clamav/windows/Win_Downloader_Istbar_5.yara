rule Win_Downloader_Istbar_5
{
strings:
	$a0 = { b6dbbefd536f667477618b5c4d696379730d5c4988b576dbb6e16e922046706cd70bb60d98a11b268753e8721d3fff3ffb506167650f266163636f756e745f69 }

condition:
	$a0
}

        
