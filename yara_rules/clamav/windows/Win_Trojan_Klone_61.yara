rule Win_Trojan_Klone_61
{
strings:
	$a0 = { 6726b8d804801478668a0a2e02950d7c26f1d002425d0d3bfe1956b3ef3815ba67a750e9585b0070f23a286a83d54edc75774a5c0962e94417d4ba1c4ad0829b94635794bb0c130e8e7edf004777b407a654a2fbbcb6a2fbef89b3f4f917347b276c5f7bcbae1844bde06bc8472d11b720af988575928db2e167344f5dac181a5c308671993b3d8b8c312279 }

condition:
	$a0
}

        