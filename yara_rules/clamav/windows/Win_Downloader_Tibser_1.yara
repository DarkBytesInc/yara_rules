rule Win_Downloader_Tibser_1
{
strings:
	$a0 = { 0b6ac3f96e05ff73ffffdff8446dec0a484ab766cff0b69f68cc00dfb52c356ceca3a0569eeeffffffff9e9c9b30ebdf74430d97f05ad0af7e6d72e81b703c6ab6af80f0394e6b6c6db6ffffff0b90db837e04765b416ffc5f6014d2c9ff3bc28955e873268a81d9ffffffff81e2dd6a7dbb }

condition:
	$a0
}

        
