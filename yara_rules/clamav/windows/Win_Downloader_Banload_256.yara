rule Win_Downloader_Banload_256
{
strings:
	$a0 = { f6ebe1d96e23dc52b23a24e08ca8b89f5fa2860a8f79a7bad50db68ac3d1da489a9550519cf381c5a6bbd68fb847aeb7f74b77c7ee6b481c1b123dd4700f20b64dfb61b1b9993f122875eeeeb28b4ee2d76a3b40fa5d6119ddec }

condition:
	$a0
}

        
