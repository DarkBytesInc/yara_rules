rule Win_Worm_SomeFool_19
{
strings:
	$a0 = { 75e249b1c56a25ab8f09bca13ac5c2cde66c4620f2150515bb13259a22cfc8cdce5b1f23bc33f35f7cc67c63a569013174e0619d06c84d3ede8bc2439fe8051509e5c7f604d282fc58bad9ed1c5c129a }

condition:
	$a0
}

        
