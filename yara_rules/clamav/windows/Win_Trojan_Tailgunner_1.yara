rule Win_Trojan_Tailgunner_1
{
strings:
	$a0 = { fc8945ccc745c4080000006a20a5a5ff75a8a5a5e8d8e4ffff8d4de4e8d6e4ffff8d45c4508d45d4506a02e8a3e4ffff83c40c8d75b483ec10895dbc8bfcc745b40b000000a5a5a56a016a2bff75a8a5e8aee4ffff83c41c8d45a85350e86be4ffff536a09ff7508ff5594508d }

condition:
	$a0
}

        
