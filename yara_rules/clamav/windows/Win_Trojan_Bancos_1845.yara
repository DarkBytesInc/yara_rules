rule Win_Trojan_Bancos_1845
{
strings:
	$a0 = { b3cb7a3d4c6e462c57e1671b9bac6cbd09bdcd3ab57fd59858db844b5d277cd429902d887b98d110498c38738bc6ef7002d6519ccb2cd5d213459826d2d38db7490686725ad8 }

condition:
	$a0
}

        
