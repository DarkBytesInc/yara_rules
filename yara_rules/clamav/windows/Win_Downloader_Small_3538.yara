rule Win_Downloader_Small_3538
{
strings:
	$a0 = { d4607f6c6dd46e6c6cec5475706c6cf7a9cc7c6c6def3080f90090806d6c6cbe1f6dc2f40a94766c6c6b43d4706d6c6cf9b09080bcd4507f6c6dd490806c6dd46e6c6cec543b6f6c6cf9b89090bd54b16b6b6bf799c87c6c6def3084f02c7b }

condition:
	$a0
}

        
