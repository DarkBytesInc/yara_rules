rule Win_Trojan_Bancos_1215
{
strings:
	$a0 = { 5c807fecb7ba1cd3dae039dcaf1dcd7efcf301bbff2a51bca61db30638f4e5d58731a541822f036e348ce728c919c0e6314d6052ec1f145ea336f7c7f880a811929d9c1bf0d38bb241bb32bcd785ff1182d2085cd5f8e1bc3c511d3d9129fb }

condition:
	$a0
}

        
