rule Win_Trojan_Delf_2234
{
strings:
	$a0 = { 53b8bc304500e869fcffffb201a148264500e8bdf6ffff8bd8ba010000808bc3e84ff7ffffc743183f000f0033c9bad03045008bc3e8a2f7ffffb808314500e8e858fbff84c07413b908314500ba2c3145008bc3e887faffffeb2b }

condition:
	$a0
}

        
