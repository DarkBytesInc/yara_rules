rule Win_Downloader_Delf_1083
{
strings:
	$a0 = { d2e7822608b3b98ba3c7b1c6fcc82c25c1840971ea173e479f36ab3840a8600a20ed3693487bf4d7615afc8ce602f9981e065e1a21ffcf91d871eb816cb048fe33ec4b75297351e32a3ad5b2249c39cb }

condition:
	$a0
}

        
