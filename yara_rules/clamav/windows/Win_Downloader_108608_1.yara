rule Win_Downloader_108608_1
{
strings:
	$a0 = { 83ec1?56[0-100]3c3040006844304000ff151030400050ff15183040006a006a006a006a006a }

condition:
	$a0
}

        
