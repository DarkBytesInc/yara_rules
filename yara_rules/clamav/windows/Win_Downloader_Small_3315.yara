rule Win_Downloader_Small_3315
{
strings:
	$a0 = { 5f22da81d81a60984797cb3b0b19861655aeed9d1eb90e9a91cc447f52fd1740df6f44d95ba5f57ddd200dc8a5119886297cf7e0ddb32ebfc1bb2812c2fa2e9c407ae7b1abf429fdc65c1a4a75f5d6418e3c0d4e47e3bc91b3eb }

condition:
	$a0
}

        
