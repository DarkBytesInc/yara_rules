rule Win_Trojan_Mybot_8291
{
strings:
	$a0 = { 255810f6d76b1517cf70cde01fb735107e6bd38443718c5a797b7d7d95146edc8963b3e41b2bb4ac1be3dd47b98be90fb1e90282dac8b59d8ffdb7bdbf6b06fd9ecd4d0ee8568f9597993211c6f8a5f50ca9c114efca38f1f7f9fb1433ec5908082020f4 }

condition:
	$a0
}

        
