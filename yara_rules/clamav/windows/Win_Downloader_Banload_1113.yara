rule Win_Downloader_Banload_1113
{
strings:
	$a0 = { 24533bcade17edde72ec0609f4caad8ff3852a310eabbe0fea8a7973b9f548ed7dac1e2b6712b39635136250bb01e2ddb74ef1ad2c23ad04a72aa2ad851819c2d2bad4a8f18355a5b660a63b806c5145b685 }

condition:
	$a0
}

        
