rule Win_Trojan_Hupigon_957
{
strings:
	$a0 = { 74bb7edc99db7172df3ba3fb2718b7c0123f88d3038129b51eae23ddf701ba6c76790266400ffa3ac4a9ce5c34c28bb4a4e65a4c413b0c2c383dc3d21845f0477ba727b7637f5e53b3948e0eabc3376bc2f0dbdf619e41cae7b2a69a30e9b934237defda5eb651671c }

condition:
	$a0
}

        
