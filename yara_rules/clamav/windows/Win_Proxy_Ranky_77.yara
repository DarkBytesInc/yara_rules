rule Win_Proxy_Ranky_77
{
strings:
	$a0 = { f097dd8a07a0d8caffbbf24a7a123a88320b18baa59f006b5446dd30507dcec8e4301ddff94fe0009068e448a57f6a4eac6681269c03b49ca77fe743273aa870e80ab4d2dbb7012f62e7354677d43d461224b40c61daf9b267fcb130de736a10737c07eb9f2193324a30a5296d3183c1d0234ef38cb155160a273f }

condition:
	$a0
}

        