rule Win_Trojan_Bancos_630
{
strings:
	$a0 = { 2ccec5346a84ecef4454e180e44f4d3e562034aa4bed3190b075efcdd142eac91bb50ba0f682e93b0950a82eded741ebb661079cff7894cd3bb54b77fb674e4e8c988b1e9c378b2909b3eae6bd8a6f5fc7aba078e4a0aee4ce4dcf5e49f73021af675b02a6dc65d47e0d6caeeed1 }

condition:
	$a0
}

        
