rule Win_Worm_Gaobot_14
{
strings:
	$a0 = { e3e255431ca0344de113412c4c6b5f490eddaa125c4a39be05afed91d03d7f9a696fcb818fd125b3a1ec908f30479f7d3bb7f80b1c5392f1578b1848bba3e4e46bf0c6ff3134bf6bfcba231a3c04cd21 }

condition:
	$a0
}

        
