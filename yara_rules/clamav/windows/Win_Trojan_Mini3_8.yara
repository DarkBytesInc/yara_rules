rule Win_Trojan_Mini3_8
{
strings:
	$a0 = { 90e9fa019c9080fc4b90743e90909080fc3d743690909080fc43742e90909080fc6c74269090903d3df0750790 }

condition:
	$a0
}

        
