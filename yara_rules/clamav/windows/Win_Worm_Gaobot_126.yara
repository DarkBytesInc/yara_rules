rule Win_Worm_Gaobot_126
{
strings:
	$a0 = { d2cab110cdffd63304a6b958cdb50b1cc540da8fd3aabdba5d5da29714c1e2e915707a506f7827af5ef1fea32da90311eeb02fcb30eef21b1466608c9992ce123c78a2af94a944a53b5cbcd51e1a2498a793fadd7b51f5931dde04 }

condition:
	$a0
}

        
