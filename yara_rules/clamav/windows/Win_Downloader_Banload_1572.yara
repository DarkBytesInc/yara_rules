rule Win_Downloader_Banload_1572
{
strings:
	$a0 = { 47812710015201403c397f53565c5959373501c00a032c6e464a5641277653557a9380115683371512567c726072c4e0c3f39830004e380205486e8b9b9a9989fe300460ac760a8d7a30b7ce8a25beeeab9182090340b7d282bba1b6d2346b46026847ca82a1d4d202b05c58bc20fd8a3d6937a2cdc0b22fa30cd4993d }

condition:
	$a0
}

        