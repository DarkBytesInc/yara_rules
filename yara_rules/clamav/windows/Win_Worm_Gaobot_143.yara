rule Win_Worm_Gaobot_143
{
strings:
	$a0 = { 9f8d8bf823d0a99afcff16918d8bf925d0c99bfcff03d839040001169913cbe0a1d0db81fcffadd4021a0b31f3ffffa1169f8c8bf827d1479afcff17918d8bf82dd0679bfcffa0d0616a0000b2a0d131e4fffe0389790900001a1b31f3ffff8d8bf82ad03f84fdff1b1b }

condition:
	$a0
}

        
