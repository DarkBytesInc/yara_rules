rule Win_Trojan_DNSChanger_155
{
strings:
	$a0 = { 62a3c8aaaa7a025afd89fa0bcc7374e50f9d3191f2e9475b641ff1e10ddf04076b71c5bffc2d798ed55b6a54252f563c74cb6e1ce0ae0b6e183541775e2137b265d77a9a8df42a8367312af5a1a9dc9496c666a82d3cbb7cf1ae3a1acee79146 }

condition:
	$a0
}

        
