rule Win_Worm_NetSky_5
{
strings:
	$a0 = { a784fc6ebce61e7adcdda9d791e3c9feb9054eef6427ce47947d5116d51dec33df88b6b1bfae7ee9055b5bd75056a543bd33f96038fede6ab38aae0807e827bd4640624a2fb66b41a66deba450d99562c4b849b2684e16506a69bda5fb3a16236890d8ff }

condition:
	$a0
}

        
