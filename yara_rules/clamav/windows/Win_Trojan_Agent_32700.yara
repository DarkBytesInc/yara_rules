rule Win_Trojan_Agent_32700
{
strings:
	$a0 = { 4b8ddb1910a0573da565c7be62c64519c8fc4910c372bb360a8762c287c054b8cffb395d7b5ebd394d8c796b903054ce9cc5494658e4ce5c4c1b137f6777e109368917c3 }

condition:
	$a0
}

        
