rule Win_Trojan_SdBot_4017
{
strings:
	$a0 = { 2a2f9fde50580abef177cea8ea1795fd25c11321a89ac26a31de39865f8e6ce48accbf83873b6c86a542e498eb655ef28ef94d96cd9995d836dfeed2068f6a1093e5767260eb258e84bc7ecc686fa6c2c8de1ba44be9 }

condition:
	$a0
}

        
