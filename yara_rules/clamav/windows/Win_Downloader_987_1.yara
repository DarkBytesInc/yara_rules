rule Win_Downloader_987_1
{
strings:
	$a0 = { 01b29c0ad46e06db0f0868456c841a6dbbd9badd0c0006d265b5c4e1d70b4a54b39dd506d92e03d9ce56aacc33dc06d7d26c869b10f214264eda645e9aedc8d6ce5709d16b1cb1a41c8bbad90bd372b57d69d1f931033c83769f7305 }

condition:
	$a0
}

        
