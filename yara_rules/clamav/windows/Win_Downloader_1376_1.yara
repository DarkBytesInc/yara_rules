rule Win_Downloader_1376_1
{
strings:
	$a0 = { cfeebab630747d715750063cfc4582374bf4282aacabc50a429521a2b65b3e008c513438a93c05be3c1ba1415956b1d6b263d51d146d475cd2459243a682de57ab6ccd931a3416c4e1f60d69627bddb6dd1d833210d3069a704421289faa606465e2fe45951b }

condition:
	$a0
}

        