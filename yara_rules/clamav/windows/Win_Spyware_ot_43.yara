rule Win_Spyware_ot_43
{
strings:
	$a0 = { 83c40c8365e400ff45eceb0e8b45e48a5435f0885405e8ff45e4468d4df083c8ff40803c010075f939c60f8663feffffeb205369c35c010000ff3405c4 }

condition:
	$a0
}

        
