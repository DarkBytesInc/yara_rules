rule Win_Downloader_Small_2236
{
strings:
	$a0 = { ee550cff89e580ce3381ec9400000081ecfc0c000089e380ccd08925951f4000a15960400089834e090000a15560400080ea0a8983b7060000c7832a0600000000000080f1d7c7839207000000000000c783 }

condition:
	$a0
}

        