rule Win_Downloader_Delf_362
{
strings:
	$a0 = { 496e74136e65742045787020720b5cdf9c1dfe737663686f737426371f687474703abbffedf62f2f6e79236e7319792e636f6d2f626f74392e7a94fd54d86970576f70656e0000d64d0c44022732138bbf277b87b9070301072f0eb4ffff5f2e104413c400cbccc8c9d7cfc8cdcedbd8dad9cadcddde1e0469fedfe0e1e300e4e503495b87acafcf }

condition:
	$a0
}

        