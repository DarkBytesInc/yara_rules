rule Win_Spyware_Banker_5698
{
strings:
	$a0 = { c61ed9cc2ae0e840c117e82b952286f3adb98786913c420a4a1f3d0b6cce72c45d9f67a6988cf896899d0befb1ba69e54be1491e309c81e3b8af729e338c6faea08a1874b51c7d3306becc8faded14f11d33680eb40f0ddf3bc2 }

condition:
	$a0
}

        
