rule Win_Trojan_Hupigon_569
{
strings:
	$a0 = { a814e4c773c935ae7415de0c108084ab16de494764de680a13e691c8073afa77cadbfb61e0a8b9aa71d7afdb6a5171f556f74d4f744f6a48c5d7edbeb2d526fe8af67154b66acba8dd8909d830f5a25b3f0ea43f90a05be9c1f08a8fa21e23230914f5f0be78df0566 }

condition:
	$a0
}

        
