rule Win_Worm_Lentin_2
{
strings:
	$a0 = { 5449564952004d43414645450f4e4f52544f4e075670bbfbee4339352346502d57490f494f4d16 }

condition:
	$a0
}

        
