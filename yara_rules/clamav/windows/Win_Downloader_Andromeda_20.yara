rule Win_Downloader_Andromeda_20
{
strings:
	$a0 = { 689c000000680000000068e4ae4000e8fc2f000083c40c6800000000e8f52f0000a3e8ae4000680000000068001000006800000000e8e22f0000a3e4ae4000b870a04000a3ecae4000e8926d0000e8b46b0000e856620000e80c600000e8de5f0000e8d84b0000e8064b0000e87c4a0000e8c5440000e8e5420000e8723d0000 }

condition:
	$a0
}

        