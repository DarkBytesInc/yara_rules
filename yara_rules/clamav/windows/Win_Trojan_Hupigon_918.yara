rule Win_Trojan_Hupigon_918
{
strings:
	$a0 = { c18499f21a7c50d73081b6f009d6bce9b3ad07cc79915d1b3e777a32d65dcff4da124ffbbefd7a337a383ab13531e41b286c59d1414b461bef0ba6670cb399a1451a27eb8d75641c2bd161e4d2893d75a2b61af4f4da67ff109327c8ac881f }

condition:
	$a0
}

        
