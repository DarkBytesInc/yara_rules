rule Win_Worm_Autorun_359
{
strings:
	$a0 = { 535368bedb59bd6820e1ee2968d49311ae68f1ee634d687a424de9c74424186b68ddb68d642418 }

condition:
	$a0
}

        
