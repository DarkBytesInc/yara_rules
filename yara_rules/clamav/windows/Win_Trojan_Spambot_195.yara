rule Win_Trojan_Spambot_195
{
strings:
	$a0 = { 6b5ffcff7f332daa50874ffe4a67a20a2b39e6da7265c80c823ba3d868fffffffffe087fcd5aac4f7c557ef80f8e91c38e99d3e7416dcebf84655fd58be174b7c2ffffffff86ed999b8e268374e420e359b9f9c641954a59a875cefa92e3db666639689c42ffffffffe5fabc05b8 }

condition:
	$a0
}

        
