rule Win_Downloader_Dadobra_181
{
strings:
	$a0 = { fc81271001e7b6f5f7f4b09e838b8c82eaea01c00a03db9bbdb7a9bcdc83a4a0b15e80115683fccecf89a1a9b571c0e0c33e2dfc1d03e084b9b0ffdbc0d6d5d4c2ab0b4300c62b55d82d65fce4ac58e29bdce4fc26f831008fdde6fae3857ffc662465807f35171b1f00cb85b56b38821726f5fc6a590d2901e009593e }

condition:
	$a0
}

        
