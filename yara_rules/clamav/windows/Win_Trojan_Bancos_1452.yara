rule Win_Trojan_Bancos_1452
{
strings:
	$a0 = { 1491f48e58b9f19bfc0059cff6127939e22895f4eb7832fa626c4ff3618423a85b63dc218b06c247e4c186d7372f211fff6ce0b43449a46bbf2b0052e2299a32f72151f0a43d75b61b6c759785db8e9f7ddcb81bfa67e53a828427cb05 }

condition:
	$a0
}

        