rule Win_Worm_Stration_410
{
strings:
	$a0 = { 2b4ed90e75d8b1c03332840495fe6752eff0d53eacea8e9c20ae45f4806e9cac0123709ffcab0ac07df02626009ca14955b9e1fb043922d9db94f38c6c25376682bf18823a0436f3f52e8d7f614fe02b }

condition:
	$a0
}

        
