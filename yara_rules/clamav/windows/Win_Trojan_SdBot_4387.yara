rule Win_Trojan_SdBot_4387
{
strings:
	$a0 = { de884daf97096fb49ce48d375ee60ad55f49509cfaf1207390d1f47d01339b34306fab3d8413307db6c2085cb9beb672f87dcaf4152ac0056305772a6897972ab0c8277084051b698d6fdb430d5c1658e10a9a0eaa75b3519e7f7a8b849f0275930c1adcb4cf8aa25ab6eccdb83a125c0e6b1cd78454e75712f20464ae753f84 }

condition:
	$a0
}

        