rule Win_Trojan_SdBot_4051
{
strings:
	$a0 = { 39ed70ab9f33c2a8f9cc00254a1b21008bfd62fcbf2b061801588be2a23ab1b8eabe66154791163a74e49dae0967bb80de23ff2e4ac46bc23fc13d01102315009ffd464a57e6e6ed13f02e6a6d40a0a6d9d892b37856 }

condition:
	$a0
}

        
