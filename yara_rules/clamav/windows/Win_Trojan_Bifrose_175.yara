rule Win_Trojan_Bifrose_175
{
strings:
	$a0 = { 168a1c5b1788009934e1da3e2513a900cb1e31f530de045f58588f009a7c1a2bc72c8317c29b92008fb6bb20f5c400b180a9efa5c97ae700247616e219a35a0b005c981a }

condition:
	$a0
}

        
