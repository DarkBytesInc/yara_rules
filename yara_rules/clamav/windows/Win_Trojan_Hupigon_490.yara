rule Win_Trojan_Hupigon_490
{
strings:
	$a0 = { 7a2fe2967d74a985bad4a522d5711fe71179956f73960cd2e5c9d40339cdf433cd9fc9747b1b8275654b6f08ed3c66850e3905dfddcf40b6730f20bd8160a1f91154e7800a062c89cd5b2dd9d9eb }

condition:
	$a0
}

        
