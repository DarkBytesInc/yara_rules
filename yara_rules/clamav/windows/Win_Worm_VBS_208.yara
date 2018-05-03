rule Win_Worm_VBS_208
{
strings:
	$a0 = { 6f6e206a6f696e3a233a202f6463632073656e6420246e69636b20633a5c706972636839385c }

condition:
	$a0
}

        
