rule Win_Joke_Kilroy_1
{
strings:
	$a0 = { 4b696c726f79206279206c697a61726440636c61726b2e6e6574 }

condition:
	$a0
}

        
