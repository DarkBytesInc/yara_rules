rule Win_Downloader_1300_1
{
strings:
	$a0 = { 10ffd76838850010e8abbbffff5f5e5d5bc3cccccccccccccccccccccccc8b54240c8b4c240485d2744f33c08a442408578bf983fa047231f7d983 }
	$a1 = { 697479000000006e65747365637500696e746572000000d1cfdfc8d0cfe3ccced3dbced9cfcf8f8e0000005354415449 }

condition:
	$a0 and $a1
}

        
