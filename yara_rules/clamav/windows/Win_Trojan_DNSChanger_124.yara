rule Win_Trojan_DNSChanger_124
{
strings:
	$a0 = { 4ded9d5dd38b27600aa4a6a6f04ee1afa6a69d65ffa9226ea6a6a6f6f5ce59a9b9a659b362b6e6a69d652fe35aa9223fa6a6a69ffbb6d3bef5cca2f55993eab7e6a6f5f559d35a59b3d2b7e6a62fe3522ddb5a9d5dd2d32dd3 }

condition:
	$a0
}

        
