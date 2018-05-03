rule Win_Worm_Gaobot_603
{
strings:
	$a0 = { f1c200999fad82640e3ad90027ceccbd6f40df50030f5f51109f11bdc08d6490e4006a402b301fdac5ef0039ccba038384aacf008828b70570267269004a8cde0a0c93df64009fa48657b5 }

condition:
	$a0
}

        
