rule Win_Trojan_Small_3915
{
strings:
	$a0 = { 1e4651ebe121c5d8e147ce63ea2d0ca7dfc303af3d4c59eb18400c63fc1a5b59e31a6ef22ec279f7ddd8e3ff1ec386e7de4c49f753cb36afca0b873ce7c25bee54cf5a4536c279f7ddd88bff1ec38e2457d343ef69 }

condition:
	$a0
}

        
