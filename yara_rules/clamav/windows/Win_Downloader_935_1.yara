rule Win_Downloader_935_1
{
strings:
	$a0 = { 5732f0cf08f56cd8c4235fcc680288edc0e8cc1b908f6be6cac318bb01835a67f86cb63ded5402a78a878d7db04905f02b50ed3e5c2ccbe736c07c0c73c527a4a4af6600f8ca04d32d83ee09b59d21a4223ae183085311e7597cee3c }

condition:
	$a0
}

        
