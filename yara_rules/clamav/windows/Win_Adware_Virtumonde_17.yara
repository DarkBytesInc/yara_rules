rule Win_Adware_Virtumonde_17
{
strings:
	$a0 = { c13c46d439ec855354834bd1b575e70105a08bc50255e6821d35be7a8651caf0b4ecaa133f62c380078258c6b2e207fdfdabb89841dc894f0c06106a65993d7ca7b29acb62563bb4c085e3636df1797e }

condition:
	$a0
}

        
