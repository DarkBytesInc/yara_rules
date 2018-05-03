rule Doc_Trojan_Ninel_1
{
strings:
	$a0 = { 74696f6e2e547970655465787420546578743a3d22cbe5ede8ed20e2f1e5e3e4e020e6e8e2eee92021212120d1e5e3eee4edff20323220e0eff0e5ebff202d20e4e5edfc20f0eee6e4e5ede8ff20c2ebe0e4e8ec }

condition:
	$a0
}

        
