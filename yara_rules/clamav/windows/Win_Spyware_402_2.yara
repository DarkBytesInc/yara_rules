rule Win_Spyware_402_2
{
strings:
	$a0 = { 72af90a98526b6e287bb726d9327b4c2b841aeab7c9306c520b1da5243b89f7406e4f270fec026e0136e41d5befb42bdd82a066b442ca8adb0cd4f9dec0ecc343de4098a949eaf508651c318df13 }

condition:
	$a0
}

        
