rule Win_Downloader_Small_2579
{
strings:
	$a0 = { 55b1ec89e52c5f81ec9400000081ecfc0c000080e46f89e38925eb4f4000a12c60400089839a010000a1286040008983 }

condition:
	$a0
}

        
