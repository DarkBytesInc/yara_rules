rule Win_Spyware_WOW_94
{
strings:
	$a0 = { 8b4424088b0d00990010505168601000106a02ff15f470001085c0a30c9900107503 }

condition:
	$a0
}

        
