rule Win_Downloader_918_1
{
strings:
	$a0 = { 3ec9bd1b74ca0b9042e8929c2d482a2b58a5c345ec61ebcd32f0d4e848a7529ed234cb049a0f14120a1a23fe1c362809621f24af079aac2a83ce20404d115e091fe8309bd5c42158 }

condition:
	$a0
}

        
