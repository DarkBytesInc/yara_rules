rule Win_Trojan_Agent_33634
{
strings:
	$a0 = { 4ae9c1d742c7ea0e28810f7e0d55c3910e748529896988bb7d91a57f2baa885a3ead65425756d56cb7e83525030d58e1e545342eb31125eb3b83fbd6d1af6e9a85b57bcd0703420fae81d9a6bdffbca232db }

condition:
	$a0
}

        
