rule Win_Downloader_Delf_1064
{
strings:
	$a0 = { a6469aca6bc3edf68ef01128ddba5ab19c8f2f4279e7c7acac9b1026c5b813014110789338f8da0ec961ae88439e13c9664ddbea7b272e415031ce41fc2ed00ae09751d3d91c63dbd99f43f07e6d214c044e9b9a6c }

condition:
	$a0
}

        
