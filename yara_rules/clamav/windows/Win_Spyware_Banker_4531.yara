rule Win_Spyware_Banker_4531
{
strings:
	$a0 = { 8afed9e0fda47b94aad104b6b600a02617ebff191755fec1a7ca73f28c81374589d78ae9b764a34963899bd8ad6686e46e94ef1d3694be9b8a0e31c0fd52adbd6f265de593bef9d0ca3e4b211c95e910cee229cd8f8a6166be602b41e99900ff391f4536 }

condition:
	$a0
}

        
