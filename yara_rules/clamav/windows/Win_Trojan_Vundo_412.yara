rule Win_Trojan_Vundo_412
{
strings:
	$a0 = { 50eb10e8dca8ff464fe951c00000ccccccc94ae8fa0100005159fec88ac12344242058e822fcffff9090eb106a6be876c7ff46e85c34ff464fc9ffd590eb21e91d960000e9babb0000e898c5ff46e89bddff4642e97ceb00005ce9ae3b000054803db556 }

condition:
	$a0
}

        
