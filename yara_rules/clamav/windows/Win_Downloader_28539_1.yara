rule Win_Downloader_28539_1
{
strings:
	$a0 = { 538bd8bab4c94400b8d4c94400e83effffff84c0740c6a006800ca4400e81296fbff33d28b83f8020000e88583fdffba20ca4400b840ca4400e812ffffff84c0740c6a006870ca4400e8e695fbff }

condition:
	$a0
}

        
