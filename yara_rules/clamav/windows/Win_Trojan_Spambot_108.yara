rule Win_Trojan_Spambot_108
{
strings:
	$a0 = { 654c0907daf5f9c8e7ff9f297c23de29279e3366d9e4aaef06bdffffffff65b7a04166f78761fe1f407000388875f690933dfdc3de2b9bfd6ecc9e4af8f9e8ffffffb9b062bb79f02da145a8d8dad49460639fd957a79abc9b34ad7751f8ff7f28f19d31cfc7acafef7a076eaff2 }

condition:
	$a0
}

        
