rule Win_Downloader_Small_2578
{
strings:
	$a0 = { 5589e580ecb881ec9400000081ecfc0c000089e38925ee524000a1286040008983b50c0000a12c60400080f6b389839c }

condition:
	$a0
}

        
