rule Win_Downloader_Small_2670
{
strings:
	$a0 = { 2022236323712f7065798e6ca754475930fe4d3632f21c0cfe41c0356be4393232dc2924fe1d27cfb1e7fe11c248fe05ff32f27c7e0bf9e360feed7873e43932e150fdd590fee7c8c8c8c96cbd44ff2323cf91b1fcfea554993c479e23c0fd8dd8fe81f7e08c8ca875548f9191e7486930fd5d3c7c27cf9151d0fc45fd2f398c8c8c8cb02d1821c626ddeb47e3150b095cb2e374a636 }

condition:
	$a0
}

        