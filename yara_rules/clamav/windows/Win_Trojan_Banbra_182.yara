rule Win_Trojan_Banbra_182
{
strings:
	$a0 = { e58470cdd5d3ac4ede783b2a5cb2006afc3f58151a9e3be2a3f514477d5c5443613caa5bdb658a26ece78a1b5da04dc3dc188959a9bfb87b34b442807ce12b771d889f5e93311f6bb7ebf9ce1b0da09bdb06e459c3dcd5100a43b27be5e48f36169c7fec077bf637d34e3140855ea26065e8608158cdcc2a14b7883eb84ada542dfaa0718bac20b7e5ed2d67 }

condition:
	$a0
}

        