rule Win_Trojan_Vnu_1
{
strings:
	$a0 = { 4e55bf2e01b9f30180353847e2fafce800005d81ed13015e5e81ee00018dba2e01b9f30180353847e2fae99a00486979612070706c21 }

condition:
	$a0
}

        
