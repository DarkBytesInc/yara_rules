rule Win_Downloader_480_1
{
strings:
	$a0 = { f845429aac29d68e2648efc03c967412f1156b1b9ce53b389afd55d2ce2b3758e3a3e9960a365620a9dbe74239db9aa2392ba39e33708df03f8b71f81ae5dcc02b6279d5a8c39a35d18223ee460f }

condition:
	$a0
}

        
