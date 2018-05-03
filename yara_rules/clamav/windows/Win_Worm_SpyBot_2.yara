rule Win_Worm_SpyBot_2
{
strings:
	$a0 = { 3a435134b04f60095b737562375ab253a3b14b032f62b56d85ad3b3a46e34b9d72cfda0f0e7c6661642b5b6a0a1c3abc }

condition:
	$a0
}

        
