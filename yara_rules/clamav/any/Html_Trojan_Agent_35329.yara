rule Html_Trojan_Agent_35329
{
strings:
	$a0 = { 2977307330682e72756e28662c302c66616c7365293b763d313b627265616b3b7d696628666675306330736b6f2e66696c65657869737473287a3129297b666675306330736b6f2e636f707966696c6528 }

condition:
	$a0
}

        