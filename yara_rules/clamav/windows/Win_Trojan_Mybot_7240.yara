rule Win_Trojan_Mybot_7240
{
strings:
	$a0 = { 376a04c22a8fec8736fa987ce5bd1b524b55fb8708042a8832852a2de92be2c466e57f825bc52fc1956475916192055d49a22273dcd83940f0d3a1b5468d4294e47a3309effacb56ef5f581cc63f }

condition:
	$a0
}

        