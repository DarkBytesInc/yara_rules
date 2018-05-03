rule Win_Worm_Gaobot_68
{
strings:
	$a0 = { 3984ad68449285230bd814c546189aedb99825d173672ce1d42d42e9b9b638e61c0cb388c65feb6ef2660a8320f3635646dee5dc74c2124638af2b4b1a7e6e4c }

condition:
	$a0
}

        
