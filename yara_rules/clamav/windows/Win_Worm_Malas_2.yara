rule Win_Worm_Malas_2
{
strings:
	$a0 = { 6880c8410050e8??1000008bd885db5959741f68b005420053e8??10000053e8??12000083c40c6a038d852cffffff50ffd7ffb520fdffff8d852cffffff50e8??0b00008d852cffffff6884c8410050 }

condition:
	$a0
}

        
