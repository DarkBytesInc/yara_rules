rule Win_Trojan_Divina_2
{
strings:
	$a0 = { 0506060c6c05000367f2800567f7800506060c6c15000603050569036d696e0f6c0a000369036d696e0e6c140006040569036d696e0f6c28000369036d696e0e6c320006061e6464672b806a7e2020202e202e202e202e202e202e202e202e202e202e202e202e202e202e202e202e202e202e202e202e202e202e202e202e202e20444956494e41 }

condition:
	$a0
}

        