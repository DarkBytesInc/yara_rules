rule Win_Downloader_10261_1
{
strings:
	$a0 = { 5568d33a141364ff306489206a006a008d45fce829ffffff8d45fcbaec3a1413e8acf6ffff8b45fce88cf7ffff50a1a0401413506a00e826fdffff6a006a008d45f8e8fafeffff8d45f8ba003b1413e87df6ffff8b45f8e85df7ffff50a1a4401413506a00e8f7fcffff }

condition:
	$a0
}

        
