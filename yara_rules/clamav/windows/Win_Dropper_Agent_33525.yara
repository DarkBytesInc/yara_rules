rule Win_Dropper_Agent_33525
{
strings:
	$a0 = { 6f1863295715ad5ed2ed1ff9ae740693cadad0e9804c313a65a8d7c6c3dbfae8adf039e73da4f6e3a32515ae73c835ab0752fb39a74dfa99cc0a880ae968c94afc15f36dbcb02e32ba5e60b0746d3431ce5b5c2a }

condition:
	$a0
}

        
