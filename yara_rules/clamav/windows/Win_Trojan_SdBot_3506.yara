rule Win_Trojan_SdBot_3506
{
strings:
	$a0 = { 8513999dc11eadde0f100b4025cfc16ecd12994c5d13164c7d3e4dba4225aee26c12ca275c73893285ea8174c226be06c337171242ef0ccae64894191a5ff0aadebd20713262b50198892bd379d11028dfb182b44aa1cd15930d5c82b118bbfeabf59dcbe92c5f9a812ec4f475ee2f65e8be2677bae35a181cdb581b2a4f33e8c992bdaf01fa0bb955d906d0 }

condition:
	$a0
}

        