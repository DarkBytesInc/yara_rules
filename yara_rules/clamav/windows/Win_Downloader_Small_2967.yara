rule Win_Downloader_Small_2967
{
strings:
	$a0 = { 27e74dabd7417c5b3b94412bebdb9f69d3d84db33e32685afb6401040d1e235c0a2c22dd2654c0807d774c4da66fc9c80f98015b67082dce68fc5b0a538b412b87de7b656acf3ec6eda0d1d1b27044fd833cfa989a6f48d6c5485c56b9cb72cc3078e20b43fedb92783592813350602622d4 }

condition:
	$a0
}

        