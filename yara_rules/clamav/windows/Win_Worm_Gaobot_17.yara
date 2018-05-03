rule Win_Worm_Gaobot_17
{
strings:
	$a0 = { f39af200917bb775959a0d4ae19ffb0857ca3451d5faec15567316bb5f08df314422924a2e58874c1d20ca4221def0638bc51b907e1de73f9dd17ce3cfecb8c3c14ea25648164c2640d6ba3cb65e4e14 }

condition:
	$a0
}

        
