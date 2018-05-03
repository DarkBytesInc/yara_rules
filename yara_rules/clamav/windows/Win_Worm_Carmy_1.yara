rule Win_Worm_Carmy_1
{
strings:
	$a0 = { 484f204f46460d0a64656c20633a5c6d79646f63757e315c2a2e2a }

condition:
	$a0
}

        
