rule Win_Trojan_Mybot_8522
{
strings:
	$a0 = { 399d1ed0a6d227bd1ed4d6b9a462870b42c17d816eb6cf558366af0532d935007de8745501e8c1bbb866d8a332a6db4b780407da6ec622c88c0c4b9d3c00a2d3dfdb8f852bc3fa6a372e88b74aa41e6d999fea505ff4d782afb347842232f67ca2070c4d42349aca7a7acc478171ba690dce26812731b79c8b570b1b25f5ef093a77ef96ff700ec663e57106 }

condition:
	$a0
}

        