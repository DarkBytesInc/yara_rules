rule Win_Downloader_Swizzor_278
{
strings:
	$a0 = { 423235370e8eef90788658bf24fa12309deed63389a4ec248fa399ea1af407d6a2a3e1dc8918719145f8e831cc8e3144f32857792c4737fffa1440c9517b59df4b246a35001af9d4ae6cdd09 }

condition:
	$a0
}

        
