rule Win_Trojan_Hupigon_146
{
strings:
	$a0 = { cb67ea116cce3a423ffd936dd6ef5edefbedab4d693a9f22083538f8ddc319adf390a1cb317691f56d1f349aece07890f30a412fda27fa7e3ccc2a174badbe493e36026c4d5d3a8bc63ce2d08e04fbc6a26c0e9d7a8919356e0354d236ab8170bd274a61fe0578ff4e940f52f502 }

condition:
	$a0
}

        
