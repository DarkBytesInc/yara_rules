rule Win_Downloader_Small_2581
{
strings:
	$a0 = { e54089e581ec9400000081ecfc0c0000b53e89e380e9c98925c5524000a12c6040008983ca060000a128604000342b89 }

condition:
	$a0
}

        
