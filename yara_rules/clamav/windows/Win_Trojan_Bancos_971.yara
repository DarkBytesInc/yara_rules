rule Win_Trojan_Bancos_971
{
strings:
	$a0 = { 94796ed7d076a85dd3ed6d471820ea732db7172517cbb47738dc336fcc0c274ea4b41e1c8af9fdafbfd22cceeaedc7b8acfb0c739051c10f270e39a768046b36e7ae19c2f8e70a2aa23ce3b8e719e81641c4d76364 }

condition:
	$a0
}

        
