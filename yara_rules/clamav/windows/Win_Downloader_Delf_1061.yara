rule Win_Downloader_Delf_1061
{
strings:
	$a0 = { e9a0e0ce44c24b33e877613da09b564f44b17b8bf613ab95e65c84179dfe7b016b9596fdca97c10ee2b596d0927568a2d78a5e0e92cb2e1c4062ad90a4d2acc54d0c542f2eb175ad2c276f3e5e79c986624400d9ce }

condition:
	$a0
}

        
