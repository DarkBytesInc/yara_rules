rule Win_Worm_Sytro_11
{
strings:
	$a0 = { b9e3657865372e4a656e6e61204a616d51da2f58ed598242837420fc2009f6cb22ad65646feddd5fad2c60446956585d204c }

condition:
	$a0
}

        
