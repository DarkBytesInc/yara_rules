rule Win_Downloader_Small_3409
{
strings:
	$a0 = { a10f15d001db55612d044e4fb5b0b5230d4266514d0f046a3f9e2bc636c1041a2352be10cccde6488111344b85dcb31e03f1892e9c462d7bdcb28820a7a1384e34e5180e3a6ebc1a1439e88e }

condition:
	$a0
}

        
