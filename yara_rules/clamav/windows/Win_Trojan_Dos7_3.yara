rule Win_Trojan_Dos7_3
{
strings:
	$a0 = { 1e8ed88ec0be8400bf0c00a5a526a10000a34c0126a10200a3530126c706000044011f8cd880c41026a302008ec0bf00018bf7b97801f3a48ed8f7f1b43eccb4 }

condition:
	$a0
}

        
