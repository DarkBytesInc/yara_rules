rule Win_Downloader_Banload_397
{
strings:
	$a0 = { dd5cb5f30a5965717ecd2427121c614bf9f718ea130bf0b5a9510f2ed686a3ea64d479adb4ce193f70b792eff4ee913fb5f09d342f541ffa76ed78e46ddd4f5cdef623c9f2a63cf8e14fa95f7f4e76e252bbddaba6281235359f4f8026efe57ec2006b733509f8dc6e }

condition:
	$a0
}

        
