rule Win_Trojan_Killwin_12
{
strings:
	$a0 = { 617474726962202d73202d68202d72202d6120633a5c6e746c64722064656c20633a5c6e746c6472 }

condition:
	$a0
}

        
