rule Win_Trojan_Tula_4
{
strings:
	$a0 = { b8a3022d0001a37d0106cd12b106d3e08ec026803e71025174532d40008ec0bf00018bf7b9a30229f9fcf3a48cc11e061f31c08ec050bb8400ba8501fa268b07 }

condition:
	$a0
}

        
