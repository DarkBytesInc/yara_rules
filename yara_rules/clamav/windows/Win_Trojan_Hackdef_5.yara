rule Win_Trojan_Hackdef_5
{
strings:
	$a0 = { 4b01842cd38c2ceabf2cea385eea38b51b39b5a368b5a3c47a02cc367d653e694d97616c62696c6e5ecd66d4966ed4e44f75ec3afce43a7be39a73f5607bf591ebb0c3d55cdea81f9adf61b1bd4c99e62f8df9382fbf6fdbc30bd8ab4cd6b26fe7f535888f77ec5a }

condition:
	$a0
}

        
