rule Win_Downloader_Homa_6
{
strings:
	$a0 = { 433a5c43414958415c4b6170612047204e4f564f5c446f776e6c6f616465725c436c61737365732e706173 }

condition:
	$a0
}

        
