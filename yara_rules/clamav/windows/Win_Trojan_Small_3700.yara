rule Win_Trojan_Small_3700
{
strings:
	$a0 = { cb4e7244e4a4ee570c9f45eacca15768df8eefd4b3c0f27fcbd1b398cac31398ca64f78f0b4f4ede28aa484322a65780db4eefe9d34d04b8db8eefcfca642b900b4f7a70364f59a321b9ef7ee1a2ffbfcbd3aff4fdd92cb0db8eefd5ca2674404074457fa3cf6bb0caab6488214ec600307fee }

condition:
	$a0
}

        
