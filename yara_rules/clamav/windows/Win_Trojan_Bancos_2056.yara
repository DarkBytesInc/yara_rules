rule Win_Trojan_Bancos_2056
{
strings:
	$a0 = { ea68ad2623b3fd8d5fccc1c8f4844ef9d266856309a2c0846c2171a9b4b9ae2db22c21c7d16ef6ef1b5c50ba5cb4e0661c6699f0841909513b37ffc8e31c2e52637596eb487402cc886e0cfd967eae4ade80 }

condition:
	$a0
}

        
