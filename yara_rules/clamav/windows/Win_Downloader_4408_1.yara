rule Win_Downloader_4408_1
{
strings:
	$a0 = { e8e4f1ffff6a006a00686c901415a198a21415506a00ff166a056a006a00686c90141568949014156a00ff13 }

condition:
	$a0
}

        
