rule Win_Downloader_Bredolab_12
{
strings:
	$a0 = { 84ded2e5c1f711c1fb01d3f781f70f577d6881d2c0dafc4bfecbd2d066d3fa81cf583018ed4281e3b53043f4c0e311e98e0500001cc8a12a34f7d102cb6633ca66d3d181d9e87b3b21d2e5664ff7d980e7b566f7db02dabbf2dc3d07e97a01000054e1a7fec349fec1d3f781cfd3863c19c1c6168bf2b32b66f7d98afd83faff }

condition:
	$a0
}

        