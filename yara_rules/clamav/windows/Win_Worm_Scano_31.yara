rule Win_Worm_Scano_31
{
strings:
	$a0 = { 22662e77726974656368722862786f72 }
	$a1 = { 227368656c6c2e72756e28706f7029 }

condition:
	$a0 and $a1
}

        
