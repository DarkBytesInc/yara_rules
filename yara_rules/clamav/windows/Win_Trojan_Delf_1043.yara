rule Win_Trojan_Delf_1043
{
strings:
	$a0 = { d91a9144333ebdbfdfdafbc2557bddbd7626c1ab1310f057a01b7c62ed3fa535a3da3bbbb64d352a917a15830692578a874ac4bce92ecd8e358546e2a9e74bf9a6aabbcf4ef76a9aa076e89beb96def48c1988bb61fc3ecf01 }

condition:
	$a0
}

        
