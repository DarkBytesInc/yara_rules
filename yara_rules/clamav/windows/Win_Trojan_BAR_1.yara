rule Win_Trojan_BAR_1
{
strings:
	$a0 = { 617474726962202d72202d68202d73[0-2]64656c202a2e657865[0-2]64656c202a2e737973 }

condition:
	$a0
}

        
