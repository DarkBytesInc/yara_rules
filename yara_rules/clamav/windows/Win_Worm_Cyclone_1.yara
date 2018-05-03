rule Win_Worm_Cyclone_1
{
strings:
	$a0 = { 97a1eab7ef60aaded834abf74ea3cbfcd4419377ed2d55c3bd36db318fca5160c5b912a9f4dfae34a9da41d453a57872544869ddcd2acdb2fabd4aabc3140073d197d2 }

condition:
	$a0
}

        
