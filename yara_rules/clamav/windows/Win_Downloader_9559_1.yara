rule Win_Downloader_9559_1
{
strings:
	$a0 = { eb02b2745281c04b9f5f3281e84b9f5f325ae80000000087df60687e4e911e87d187d183ecfc6187dfc7042496e04000 }

condition:
	$a0
}

        
