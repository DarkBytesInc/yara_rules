rule Win_Trojan_Otupsys_1
{
strings:
	$a0 = { e8f21c0000e995feffff3b0d902041007502f3c3e9791d00008bff558bec83ec20535733db6a0733c0598d7de4895de0f3ab395d0c7515e8762e0000c7001600 }

condition:
	$a0
}

        
