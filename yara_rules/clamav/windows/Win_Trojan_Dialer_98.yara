rule Win_Trojan_Dialer_98
{
strings:
	$a0 = { 56c041c00f84c38485707615915af2bb0eb0dea74e544558555309068904c420c4a81edb08014ef116ac9bd12e5af7729b0dd7a278a711632f8a6e6f5b856796 }

condition:
	$a0
}

        
