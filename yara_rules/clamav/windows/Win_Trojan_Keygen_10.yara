rule Win_Trojan_Keygen_10
{
strings:
	$a0 = { 434f52452070726f75646c792070726573656e74732061206b657967656e20666f723a }

condition:
	$a0
}

        
