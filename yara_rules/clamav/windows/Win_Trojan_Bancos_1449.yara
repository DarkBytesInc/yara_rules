rule Win_Trojan_Bancos_1449
{
strings:
	$a0 = { 307c18c31157f6c14c3149ccb1d90f687160cad54095ab63bf7165fb35635cd700033cfccb522964b00a3e9b153c8a61908c1e341ae6bcb3674028af15bf60ec8573ae09551ebeedbd366de73b077d5ce8597e2339db3146cf6b1e6c87752e0b }

condition:
	$a0
}

        