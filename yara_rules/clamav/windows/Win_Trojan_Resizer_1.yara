rule Win_Trojan_Resizer_1
{
strings:
	$a0 = { 6d6f7665746f2832302c323029 }
	$a1 = { 726573697a65746f283030302c303030293b[0-6]6e742e77726974656c6e28226f6b22293b }

condition:
	$a0 and $a1
}

        
