rule Win_Adware_Atris_1
{
strings:
	$a0 = { 74723e3c74642077696474683d2231303025223e3c7020616c69676e3d226a757374696679223e3c666f6e7420666163653d2266697865647379732220636f6c6f723d2223666666666666223e796f75722069702061646472657373206973 }
	$a1 = { 6666223e746f2070726f746563742066726f6d207468652073707977617265202d20636c69636b20686572653c2f66 }

condition:
	$a0 and $a1
}

        