rule Win_Trojan_Pakes_484
{
strings:
	$a0 = { 15723fc6a9dd72726a0c5926906969bf952e19b5b19ac2ef9586023ef6845c648c371f234c665791a09d5f39109c342c99c64219efd15d2f80db2e3863235a5974821b039086abbfc1836aed23b04d1ccad65ead86104217d5e61f8bbc67d9d61d83a33623ec9deb803b4934bff23bb715cb2656fb1f34834c0a577ea1855701f3e32240e2890339eb02ce26 }

condition:
	$a0
}

        