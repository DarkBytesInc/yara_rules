rule Win_Trojan_Agent_33621
{
strings:
	$a0 = { db3833fd69419dcf03d5fdc816fb3015cb80de1ebca310626ac76a036b71e079c4eb52fe03b08e10cf99e8a1b95e1647302714eb2fc62878555eff81d5408703cb08ae63ab0e28f7990ee0fabc8176651f7f }

condition:
	$a0
}

        
