rule Win_Trojan_Mybot_7824
{
strings:
	$a0 = { 8516850a2d1a8eef4778041d60ee107851ddc209478341604a168140a51dc28e1476a3c0294b45a2cd4bdfa774e7fd6bdd09dfa7bbff7ff39ef9e68fcccfd99cca9a8d06f58be0aba9f3b9dae62b6ac3b5094c1fc2b0e730cd3e6a8e0bf66f098955a6cd78fb63ef795bdd3127ea66eec91790ff1b159f4e7e5a5b401a }

condition:
	$a0
}

        
