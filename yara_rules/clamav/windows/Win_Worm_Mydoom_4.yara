rule Win_Worm_Mydoom_4
{
strings:
	$a0 = { 31744f9bcd66b35c36277122583d69b830b3d96c36c36ace123967b4686c369bdd9077ca38252ef05bab313ecdeed35601072c9c06c71277bfa7dbec041d7538 }

condition:
	$a0
}

        
