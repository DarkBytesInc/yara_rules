rule Win_Trojan_Small_3845
{
strings:
	$a0 = { 38a2bb964af9b51561718aeb6ef5bb9e4ae558c677b530bc8656cf1591acb42a37fab54b6ff530155ba129aa6ea2d8b054f530b3eb35699e770a05d277b530bc86bd0aea6eacb52a378037806f1c43eb6ef5cfdf36ec70ea39 }

condition:
	$a0
}

        
