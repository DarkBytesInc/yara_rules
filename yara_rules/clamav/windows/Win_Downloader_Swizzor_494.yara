rule Win_Downloader_Swizzor_494
{
strings:
	$a0 = { 44c5b857746855595147010e1641825eb36abf6afbd95bd65794b3a2ad6558506cb4cb5516ceb7be9a1934aa2fc0a9fc82a7f5c28baba596c278a4a797e41d9c6a7fd7311f6d77c24fa642c4e6f1bc9dcc55041c8b8dda58c29bc1eb171c9f94188843c8 }

condition:
	$a0
}

        
