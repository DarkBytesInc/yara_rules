rule Html_Trojan_Iframe_34
{
strings:
	$a0 = { 3c736372697074206c616e67756167653d226a617661736372697074223e66756e6374696f6e6e62737028297b766172742c6f2c6c2c692c6a3b766172733d22223b732b3d22303630303437313136313031313230313136303937313136313031303937303632303630303437313136313031313230313136303937313134313031303937303632223b732b3d2230363030373330373030383230363530373730363930333231313531313430393930363130333431303431313631313631313230353830343730343731 }

condition:
	$a0
}

        