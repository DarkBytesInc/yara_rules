rule Win_Trojan_Gen_193
{
strings:
	$a0 = { ee9ae408fbf4f0e304fbdd1601f95dc3ffc718202a2a2a2054552042594cc020d1e94b4ffa53edb8ef1cb80202b781ecf7ffff8cd38ec38cdbfc8dbe00ffc57604ac7f7faa9130edf3a48edbf0fe1657177beafa9aedd4c7fbef9a750697fec7ed978986fefd83befc00ddbb7411f905740a }

condition:
	$a0
}

        
