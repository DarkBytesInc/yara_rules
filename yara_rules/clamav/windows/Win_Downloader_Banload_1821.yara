rule Win_Downloader_Banload_1821
{
strings:
	$a0 = { ffa17571ff0000008f0000002f0000000000000000bea0514bedd790fcffffafffffea8effe4bd679edeb95a05d9b94b49e3c450eff4d757fff7d650fffacc42ffc68c27ff5c402bff8b735fffc7b39fffe2cfbcffe6d4c0ffd4c1acffb6a28cffae7d40ffe99d29ff }

condition:
	$a0
}

        
