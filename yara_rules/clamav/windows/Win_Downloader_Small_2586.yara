rule Win_Downloader_Small_2586
{
strings:
	$a0 = { c16389e581ec9400000081ecfc0c0000243989e380f51f89258e4a4000a12860400080cdf08983af0b0000a12c604000 }

condition:
	$a0
}

        
