rule Win_Downloader_Agent_33306
{
strings:
	$a0 = { 49d07b7a573a5cbfcf4a7b5ebab3e20b16ba4a7bb97c7c3bc044f5cffc105e393b8e7d483f7c40244239f53b0a16b3b9d4c2debb7b6dfc5eb3be0bbb74df7a83fa1e4948b5de485c4a7a1605baaf92c7ba999f38f85ec313b9ca8c51957dc3937979badb4b7a5c4c7bdb4d7b5c4c7cdb4d7cf88938740e13 }

condition:
	$a0
}

        
