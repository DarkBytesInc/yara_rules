rule Win_Downloader_Small_2545
{
strings:
	$a0 = { b65580c6ca89e581ec9400000081ecfc0c000080cc0189e380e67a8925034c4000a15560400080f6788983ec070000a1 }

condition:
	$a0
}

        
