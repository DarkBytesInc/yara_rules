rule Win_Trojan_DNSChanger_134
{
strings:
	$a0 = { 480db9944688294488314688252686f636b8e04c0b61cfcdcd9b258ac4cdcdf60e94c24905cdcdcd9d9ea532c2d2cd32d809dd8dcdf60e448831c24954cdcdcdf490ddb8d59ea7c99e32f881dc8dcd9e9e32b83132d8b9dc8d }

condition:
	$a0
}

        
