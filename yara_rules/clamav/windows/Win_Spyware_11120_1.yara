rule Win_Spyware_11120_1
{
strings:
	$a0 = { 33db33c0b876304100fe00403d8432410075f64381fbda8a010075e833fbb6b6b6b12a4a8c59e68e25252626 }

condition:
	$a0
}

        
