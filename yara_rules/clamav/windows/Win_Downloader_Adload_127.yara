rule Win_Downloader_Adload_127
{
strings:
	$a0 = { 4fd99cc43c0919a8058eaddd26b55cdad7cfbd2f04f8cec0b76987267de411e2b9cde579257125266d88e5ec94ecbfb1a5cd8de1743965d75481582f73aedf7ba79a8e2127c4a4f18d5154efd494a9c9a15e5d3409e9cdf491f53d9ea708be2053a4e7269dc882ae30f0e5f4e1a71d9545b63d479d2066ba498fa4d7cd0866afe9efaaf5a6944cd7a78da171 }

condition:
	$a0
}

        