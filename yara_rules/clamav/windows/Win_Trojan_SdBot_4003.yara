rule Win_Trojan_SdBot_4003
{
strings:
	$a0 = { 47a8a69d1da8809a011ed95f2d01085de3c6bdfc5fca045efbe64c1c962c42540a82efda50e1ba14f82cbbe09c686df1566cb916b68c283457dbcb132a3ab797d726c0320bd611b2c367f71dea593f31448bbe73c71b2a313a386597e1213a37c49fbfbc }

condition:
	$a0
}

        
