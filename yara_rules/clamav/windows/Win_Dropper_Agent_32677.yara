rule Win_Dropper_Agent_32677
{
strings:
	$a0 = { 56576884e04200e8a3b3ffff5933ff8a875cdf42008db75cdf420050e811b5ffff475983ff20880672e58b3d5cdf42005333db66391d60df42007e26be62df4200 }

condition:
	$a0
}

        
