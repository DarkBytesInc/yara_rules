rule Win_Dropper_Agent_32166
{
strings:
	$a0 = { 2e8231ffc171665128b3bd05ddcc1788067e6e0e27f9cafbb2082ed4d5c60aac4218fe2f5634a25f43ee6d4e3c510f47aac92cf966f63653cdb60db60c2a6b53bb14651b892a2f7509849a6d5b9a2565d693e2442963899b6d5b68cea60c2447b691b1fa456391943076e1f821a0ce562e6d2698e49664c778f2a2c824f949e212d4b6ea6354a77846b6bbcd96966c4f9d }

condition:
	$a0
}

        