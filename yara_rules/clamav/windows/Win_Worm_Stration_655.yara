rule Win_Worm_Stration_655
{
strings:
	$a0 = { debb37202e6578650b5c0fffffcfbf0a1a5552491a0a275d786c697c6d287b7d6b6b6d7b7b6e7d64ff6f6fff64712861667b7c69086d6c268301262e }

condition:
	$a0
}

        
