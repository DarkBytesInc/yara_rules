rule Win_Worm_Stration_579
{
strings:
	$a0 = { 12ea59244754f7761a2470f6e7573c6ad9e724ad46145617cb33fb8f794e58675263b4980e9efa1bcb33fb8d288a59ae06cef4344a30e3c01afe5f206cae4927 }

condition:
	$a0
}

        
