rule Win_Trojan__1590_0001_000_1
{
strings:
	$a0 = { c100e82101ba1307b9f807020e1207b440cd21e80101582d0300a3f005baef05b90400b440cd21 }

condition:
	$a0
}

        
