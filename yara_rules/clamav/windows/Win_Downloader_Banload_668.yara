rule Win_Downloader_Banload_668
{
strings:
	$a0 = { ef57c6bee2a02023382c5c0c234a4d204904e3fe8f716594c4d8744851c63110b3c3219503a4cfe2c534c473a93a91e0630c1ff5d9d337316b91cd3a5fe00689b4bdfdc9a21ce4d1519fbf7af28034913692425e56afb63b09b685db7b51e160bffc8109f8df458ccf1b6d7c0ee571000686850a2441 }

condition:
	$a0
}

        