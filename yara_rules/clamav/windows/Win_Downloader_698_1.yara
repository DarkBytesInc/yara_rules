rule Win_Downloader_698_1
{
strings:
	$a0 = { 29b8a7d1b4b963fbb0816d4baf81e620e63137c7f99b3dd943eca80da1fdeee7e9cc5d8f486959485e71eb827b2de2f20aba7152a7c41487d82f1b9a096c2c8b7dc53f748e7caa2d5dcca97f6a1a6180dae995fe7b41e5 }

condition:
	$a0
}

        
