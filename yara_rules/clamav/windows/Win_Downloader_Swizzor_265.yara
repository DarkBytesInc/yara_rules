rule Win_Downloader_Swizzor_265
{
strings:
	$a0 = { cf5b2c2aa792467883f395caff162ea6b3d6d72cd80afcc48b2c2a556794081ea96c09918866a67a41dfb4d3a1204f5f62e828ac60584a3c98bd95f0b169d319119779d6d9042765327a6dca }

condition:
	$a0
}

        
