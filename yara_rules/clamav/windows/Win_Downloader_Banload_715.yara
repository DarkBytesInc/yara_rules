rule Win_Downloader_Banload_715
{
strings:
	$a0 = { 8890f56c0d05b67c3909edc1be74195e92865c9aa33b1eb606e2b1c3d4ff832192fa8ae3fae497d531b3ffbfaa5c18487ca92b3b2f0b1a82219f3e5eab583f93f8b36e780358e0fdf3ada9cb700e5f48efb5eaa75bac95d94b544ead5bcf872b3bf628c2bc465bb891974462326da1f3652fccb20dfc }

condition:
	$a0
}

        
