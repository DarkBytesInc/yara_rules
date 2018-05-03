rule Win_Worm_SomeFool_36
{
strings:
	$a0 = { b2e861c1caaf7b576e8623e8adaf23d1308ca0a5ef386f71f8971f7d37ee0bdb510075bfc25cd15770b592827cac3bb2492a97590977f793de46c841cd6afa128456a3b7919a71cd4b9410e6cbf87b09be57 }

condition:
	$a0
}

        
