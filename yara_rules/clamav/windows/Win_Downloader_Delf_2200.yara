rule Win_Downloader_Delf_2200
{
strings:
	$a0 = { e06e561870618876b938f5ec0ad1507c52992c8a829bb55419cf075334d0b43d3cf28f6dbe6fded1b769ad636894ba10762a68f0f77a2ea25f01202f8ecf53a1f3eb7b6f0e26fda319751f5acc79965a }

condition:
	$a0
}

        
