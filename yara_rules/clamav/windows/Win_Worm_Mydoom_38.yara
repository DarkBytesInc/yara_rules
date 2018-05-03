rule Win_Worm_Mydoom_38
{
strings:
	$a0 = { 67a8ef8e6e3179be69468cb361 }
	$a1 = { cb1a8366bca0d26f2536e26852 }
	$a2 = { d75483044ec2b30339612667a7f71660d04d476949db }
	$a3 = { 463bf77cbb80241e0020c35b6a5046 }
	$a4 = { 0bf403d0f3a49f803c3b2e750143 }
	$a5 = { 78de7e4caed0593b5d0c597c1f }
	$a6 = { f699f47d654db95989 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6
}

        
