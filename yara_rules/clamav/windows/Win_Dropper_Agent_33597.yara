rule Win_Dropper_Agent_33597
{
strings:
	$a0 = { 8f1f6142638faa9fca191dd2a3edd45bafa3e59b124d7ca46498f5bdacb602422b05f0a52a8643dc0164cdf90375252e0aa13dcf7a1b79ef92aa4c9d5b18732771f98ec46446aecdb12e0aff4cd3b07e2ffeef62 }

condition:
	$a0
}

        
