rule Win_Ircbot_Sblive_1
{
strings:
	$a0 = { 011e57bf56041e5731c0509a0107b2049add05b2049a9102b2045dc312757365723d48656c6c }

condition:
	$a0
}

        
