rule Win_Trojan_Agent_35304
{
strings:
	$a0 = { 5c776d706c617965722e657865222c32293b206c6f636174696f6e2e68726566203d20226d6d733a2f2f223b203c2f74657874617265613e3c696d67207372633d226e65776269652e6a7067223e3c736372697074206c616e67756167653d226a617661736372697074223e66756e6374696f6e70726570617265636f646528636f6465297b726573756c743d22223b6c696e65733d636f64652e73706c6974282f5c725c6e2f29 }

condition:
	$a0
}

        