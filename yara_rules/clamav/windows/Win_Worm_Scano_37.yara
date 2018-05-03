rule Win_Worm_Scano_37
{
strings:
	$a0 = { 64af6abd2a96c0cc908f2832df49668803595d6a5da6190a431ef0fd29286bc33b6e836b223065d7ed624f284d56bdfedf0db92277f05bebfc1956631ed99afdb913b735a6bd0a2b80 }

condition:
	$a0
}

        
