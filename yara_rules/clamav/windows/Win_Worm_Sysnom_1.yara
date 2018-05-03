rule Win_Worm_Sysnom_1
{
strings:
	$a0 = { 0a5368656c6c202272656765646974202f7320633a5c7a2e72656722 }

condition:
	$a0
}

        
