rule Win_Spyware_Banker_3322
{
strings:
	$a0 = { 083466e5a937e1596a23da74d439e6221fdd243df749db6ebac5fbe11a54c8d8001e9ec549a54d23211373bc7258b56fcfe31939432094cdfc57431074c47a82d52f5d9611bb }

condition:
	$a0
}

        
