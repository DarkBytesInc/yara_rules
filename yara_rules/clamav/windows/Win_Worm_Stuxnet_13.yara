rule Win_Worm_Stuxnet_13
{
strings:
	$a0 = { 60e803000000e9eb045d4555c3e801000000eb5dbbedffffff03dd81eb0020080083bd7d04000000899d7d0400000f85 }

condition:
	$a0
}

        
