rule Win_Worm_Stration_769
{
strings:
	$a0 = { 07408a0884c975f58a084084c9742aeb0b80f965740c80f9457407408a0884c975ef8bd04880383074fa38187501488a0a404284c9880875f65bc38b442404dd00dc1d00e84100dfe0f6c401750433c040c333c0c3558bec5151837d0800ff7510741b8d45f850e8e60600008b450c59598b4df889088b4dfc894804c9c38d450850e8080700008b450c59598b4d088908c9c385ff56 }

condition:
	$a0
}

        