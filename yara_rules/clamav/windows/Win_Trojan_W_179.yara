rule Win_Trojan_W_179
{
strings:
	$a0 = { 41008d95cd0d4100525150ffb5ac0d4100e831f9ffffffb5ac0d4100e8d9f8ffff8d852c0b4100ffb5b90d410050e8fef8ffff80bdb80d410000741dfe8db80d41008d85000b410050ffb5a80d4100e835f9ffffe9c9fcffffc3ab56f9bf1d3cf9bf002a2e455845 }

condition:
	$a0
}

        
