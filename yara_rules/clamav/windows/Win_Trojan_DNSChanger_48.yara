rule Win_Trojan_DNSChanger_48
{
strings:
	$a0 = { db4d4f0066b5430fe25242591d4d4be7c8c5bcf0b46ebc7aeeb3bbe7fcc5bcf061fc5b86a7341559883b1565e150430fe2b81484df34524fe2c79459b4524059883b2b0fe23803f09734ca4aeac7948c9f30bc841a4c7c8c1dc737356f7dbb5f6f7d }

condition:
	$a0
}

        
