rule Win_Spyware_270_2
{
strings:
	$a0 = { 1dfd7da78084feb87fffe8d202ec6a92d9137d1babb9093e001f9fc67b84feb87fff6a964bec822d1de4eaae02fb913a4dcf82d200e99cc67b8406be7fff6afa4bec822d1de4ea5604fb913a61cf82d2006ce9c57b84feb87fff6a66da137dd9a8988b3a }

condition:
	$a0
}

        
