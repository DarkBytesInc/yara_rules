rule Win_Worm_Mydoom_16
{
strings:
	$a0 = { 5fb804345838582edcecdbe3f30351554954cb9efedf4f07d7534154410c5243505420544f3a5a5bfd90174d41494c2852b821bd01c9115f454c4f4324b7b4ec45480b1625614b568843e0005b53bc02 }

condition:
	$a0
}

        