rule Win_Downloader_1294_1
{
strings:
	$a0 = { db5aca1b2e45788ada6b8f32d2b6e21c687447703a2f167a3a18692d73ca2e6e970f8cfcfb73abdbe17068ca9d20093166705afdbb4e3d78d10afe4409852a79320eb2331d64343ac83555a1f648017d7dfffc8701d7dfffc801d5557dec00 }

condition:
	$a0
}

        