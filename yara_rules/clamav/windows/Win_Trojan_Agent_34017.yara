rule Win_Trojan_Agent_34017
{
strings:
	$a0 = { 65e5be0fa2009d301a12a4eb206a0ea380d383c064df81ea3b0311034c71b88ac0cb69f9ee5300c62f90e0a817654a00fe02d1e1979f506d00a3bb27bacbe6e0dc00cd4c732f198447bd1df076c6403f673015cf14f6067d8e0193b32216496e5cdc084a003bfb19c3760bc8e40096a7dad2684dbb4a0016bc2d0e104ef7b5743500714501f3477f30410019 }

condition:
	$a0
}

        