rule Win_Spyware_Banker_3349
{
strings:
	$a0 = { 855646a77a9acd26117f62d426f53b6091c07249d26aee0bc4c6745a5cb8529c6ad25f13fa8cffe530f89058a93abf77fd2708946950b89710cf1e99ed019c5cb0379da603be }

condition:
	$a0
}

        
