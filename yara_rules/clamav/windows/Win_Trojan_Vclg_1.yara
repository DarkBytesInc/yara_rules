rule Win_Trojan_Vclg_1
{
strings:
	$a0 = { b90001e2feb9eb09b805feebfc80c43bebf4b80335cd21b425ba8c01cd2187d3cd21b8f2f9051000ba355983c210b31080eb10cd16b45e80ec10b9050051e9060051b45f80ec1033c9bad101cd21 }

condition:
	$a0
}

        
