rule Win_Trojan_SdBot_2126
{
strings:
	$a0 = { e17ed88be0b66bd0959fafba937c21f24a3faf5e14dc49cb1578bef3f6a2e36a5c212de82b5463b0a86e2dbbd4a4a9061baa5304dc2b312a22a52b1263f1d453664c327bd5bdccc82aa86dd9e811385285cbef88af5a99ea6d9e2c372c2cd0a71a08 }

condition:
	$a0
}

        
