rule Win_Trojan_Hupigon_824
{
strings:
	$a0 = { 8b15eb2410d65991175e65f20f224d6cb3ab72f7904df5aba32f3e7cfc4e5dbe2bd49bf6ea8a7fbb2af5d679eb5305b3d53e115dc3f26dbc84ba7f81238536655ad3d0f708332ebb462c17e31729c02fbcf3b4423dcb5d14aee0d881ecf32f }

condition:
	$a0
}

        
