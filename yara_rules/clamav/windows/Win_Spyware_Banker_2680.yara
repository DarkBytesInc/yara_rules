rule Win_Spyware_Banker_2680
{
strings:
	$a0 = { 75a6928f62cad7212fcc48b2368328fbed927858069933c87e707b5b9b532cdade7b0252e50fc05a880adce6cee946858ec697b4f7293fbd0b85235a42aa11bc92d37cdd90c4f4ef32d9156352e3 }

condition:
	$a0
}

        
