rule Win_Downloader_Small_1296
{
strings:
	$a0 = { 6a006a0068????????68????????6a00e81b0000006a0568????????ff150010400033c0c21000 }

condition:
	$a0
}

        