rule Win_Trojan_Bancos_933
{
strings:
	$a0 = { ddb347728d3b856bf48d3eec617c21cb6992bc64afa85b5ac2849e102d32e46b6dc5b6ad562d44b81704e9fd35c9cfec3eef59a48192a3ec348beccf7cf4a5dd92e5de2b3aeb84b98cbd5af79b56e74faa13cdbf75cd4fe3 }

condition:
	$a0
}

        
