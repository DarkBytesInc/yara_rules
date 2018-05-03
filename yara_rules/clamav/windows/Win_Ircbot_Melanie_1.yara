rule Win_Ircbot_Melanie_1
{
strings:
	$a0 = { 1e57bf56041e5731c0509a0107b1049add05b1049a9102b1045dc312757365723d48656c6c }

condition:
	$a0
}

        
