rule Win_Trojan_Dialer_929
{
strings:
	$a0 = { e1ac3479ca266a1606fae4c9e5ea5cd10e2a9561aa3f5b5e66a1973d83ce8bbbae6ac0ea86938822a4c170809f728bc0eb4a6bbcaf2c9c3aec1912fd0bc52abaa7bef0bb4d6d03f5df1085dfaaa4873e70f4750b97e09c6489739ef467a5e428e87ed6c1e7550a98debc9532272e6f3c1db6a83750f794f64cdb1e79a8343b53f0f4f39c39147f4b77838a6ada5c4c5863 }

condition:
	$a0
}

        