rule Win_Downloader_1123_1
{
strings:
	$a0 = { f4a2275b2397c0dcf6cc3fdae1d7d9da5e1d1a8f64decf5d019f00deee5061e36b03c69ef6d923c5acb9695a18ef64e2d7489578c8d225e9f2235fd7c17e7736188c5bddd18e05b9d49f8d96a0f2d1b644820cfab6e5731ba9630afa }

condition:
	$a0
}

        
