rule Win_Spyware_Banker_2647
{
strings:
	$a0 = { f91fc2a22ab6f6d0cf5b76130ebace35dd933a8b56a6879ef5eb9b229b66fc2d19c78dc6350040b8e04406a21ee2b753c717918a3d1a348c06c60d4880dd679c3e84a0f597ab6a4d905042bf470674b789bf587c0cba0ae733639acde0f5fdec06e2 }

condition:
	$a0
}

        
