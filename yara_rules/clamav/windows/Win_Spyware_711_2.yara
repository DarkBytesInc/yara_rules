rule Win_Spyware_711_2
{
strings:
	$a0 = { 1baff8b74635baee6491642e8ff3f7f929334af2385086caa7b4a17dc6fd337e42d7dffbed3faeb45178989b2cec8ec3fff3399cd0ccd185dd03ed3bdf3aa7abdeb6b88e583c2718f5b3cbfc37e67c4e787c5f4247b8c90f34580d5cf5926e7820d7c453 }

condition:
	$a0
}

        
