rule Win_Trojan_PcClient_40
{
strings:
	$a0 = { 35542c01008934820f20c00d000001000f22c0fb830d0c1e0100ff890d041e0100890d081e0100880d001e01005ec3cc5c0044006f00730044006500760069006300650073005c000000558bec81ec0801000056576a0659be701901008dbdf8fefffff3a566a56a3933c0803d001e010000598dbd12fffffff3ab66ab7405e8bafeffff8b7508837e }

condition:
	$a0
}

        