rule Win_Trojan_Trojan_6
{
strings:
	$a0 = { 587e4fcf556fe1271fcebce0e80b8c2a616c21fb0a8761e47d0ec34cfc36e2f73ff8bd88df19fc36230e0728e4dbda62f3c6746564b353684a80cae0ee96482a21a6366164aaaa2010c63a9712038256 }

condition:
	$a0
}

        
