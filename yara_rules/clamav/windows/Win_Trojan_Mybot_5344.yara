rule Win_Trojan_Mybot_5344
{
strings:
	$a0 = { 9d7319673dc852b83eb31e5cb5b97aefadc927b71546e58ae99702f38111c0498048a32c5150ddd1245a11abbb22e512a8e246a7be02838b2b0d4d54b8e64e8c0c151db04f0dfce2fe598fd06ebf4ed456cb6bc6dac8ad2b87549c867b3dab609caf88377e9800fcb66a5ce60f6ec18f6db3f8e7 }

condition:
	$a0
}

        