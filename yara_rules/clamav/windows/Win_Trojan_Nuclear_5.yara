rule Win_Trojan_Nuclear_5
{
strings:
	$a0 = { 5267c280673b800506076a0a3a50657273696c4d616e126a10476c6f62616c3a50657273696c4d616e126c0000645267c280673b800506076a0b3a436c6561724b6570656b126a11476c6f62616c3a436c6561724b6570656b126c0000641a1d6429690a436c6561724b6570656b64 }

condition:
	$a0
}

        