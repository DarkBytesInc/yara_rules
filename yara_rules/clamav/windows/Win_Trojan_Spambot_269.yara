rule Win_Trojan_Spambot_269
{
strings:
	$a0 = { ba320836f31407a0ca6d3b223c4f6ced9bc09027769080f6f29fffffd7ff1a9141e3af57b780df54cfa2583b529ed6dfd75cf86a61e2c1daffffffff0198a94f475764254e255572a092912829abce4162f4ff5b9c1e1dfe0692836affffffffbc82bf6a5519d4cdf808972f4921 }

condition:
	$a0
}

        
