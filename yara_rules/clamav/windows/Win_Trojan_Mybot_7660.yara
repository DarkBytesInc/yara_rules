rule Win_Trojan_Mybot_7660
{
strings:
	$a0 = { 14e76597ba13d6c063fe830d02ba456075061f0ed2094e9ef0312082c05b1c3c02155d5828b6c02a4fbfc081efa7854e22b86525544e41939af8fe0170af54f96a4c93ec7be73ebb5f5f00478729812e7664976305e69b6b061f613ce86dff24095db50a7a8a07c3b2ffdfe65e03e807b29d0f247fb760e8b0f2b4174a561f05ccc8490b1b8e4232db4b2a4421d28aea2c01977c15d3 }

condition:
	$a0
}

        