rule Win_Trojan_Agent_33325
{
strings:
	$a0 = { 4c06b4fa5e6c454049c715ade7684c232dd960bc322f99e08b8c287cd8ad1121dec8ac35c220344fb0ba8482dce2c6c2b52bfdf0df48991cae1ec910be577f40ba560e3c4538e8f931d8daea832c677ef6f940b85f229d994ed4 }

condition:
	$a0
}

        
