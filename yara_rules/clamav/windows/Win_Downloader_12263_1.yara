rule Win_Downloader_12263_1
{
strings:
	$a0 = { 2129a2512a582573c2c724d981848397841a6d3dbd56f1fa72f29d052c561acd23bb249a7d84a39ac8d9e9951d1d38ba4f7fbd04f27dfabf37412f3d21275739 }

condition:
	$a0
}

        
