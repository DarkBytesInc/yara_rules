rule Win_Trojan_Bancos_666
{
strings:
	$a0 = { 4bbe8b66baf321413ef31aafef087ef2a1ad141c43fe7421fc88f66a0785ee78e1a1d9048d5ae4ce73321a161fa0df04cea7b6a5e2532169ff3ca6243268d13f9ec0e74f702b9c077927cbc19a5cffde1b97d97d349e56f173a1 }

condition:
	$a0
}

        
