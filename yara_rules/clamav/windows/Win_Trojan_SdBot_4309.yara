rule Win_Trojan_SdBot_4309
{
strings:
	$a0 = { 5cb9e5090af74661c92ccfca3c4397c9c28b6c31c575a948c87716fa383c8571c583b54fdf6363d4b5b7830ab608559dbf679a25be065b5eb09a1f23505ef363bbf0b65ee7c45d32f8a08286e50c23b49b363ee637e0356d912b8dc1f08205da4e16a99a33962cb835af66d06311b3374f55b54d0283e5c56558540eb6a9aad2100f4eced934e274d48216ca147e4b2ddb837d96 }

condition:
	$a0
}

        