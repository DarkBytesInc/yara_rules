rule Win_Downloader_1128_1
{
strings:
	$a0 = { 80eda05564136707237c38e83934badc6d13fde464f0b2b42eceaf7cc652cc075c1fea65b1531099c111d9d1b3dae42abbed80a6edf6013bda1ec23b571d98a9ce455b759d54d6ea75b9bbe882e0c82428c1deab2d08711e460ac012 }

condition:
	$a0
}

        
