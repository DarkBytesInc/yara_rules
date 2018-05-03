rule Win_Worm_Gaobot_8
{
strings:
	$a0 = { f427b4a2e119ca1d627ce11ded233b15dfc07a4c171e360954be89293bbe1a8dfe76992a4352c09bdd1ad5c28fd8ef53aa79ba84bbcdc67e350f753afb42bd74 }

condition:
	$a0
}

        
