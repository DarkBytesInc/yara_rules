rule Win_Downloader_Banload_1066
{
strings:
	$a0 = { dd7e223e49f40b32b44d285fd739897c9bf74223298b9059e171941368b87acc9d5bbae3820f16cd6bb158dd3885ca1d7c8926676bdcca231e36d9a07e44fd755bf14b22220a548d1cf8a7c62d7e }

condition:
	$a0
}

        
