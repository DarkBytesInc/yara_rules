rule Win_Downloader_Jinch_1
{
strings:
	$a0 = { 6520706167650025733f6d61633d2573267573657269643d2573266a696e636865 }

condition:
	$a0
}

        
