rule Win_Worm_Furby_2
{
strings:
	$a0 = { 6a0068dcb140008d955cfeffff52ff158c1040008d855cfeffff508d8d70ffffff51ff15b4104000c745fc1b000000c785b4fdffff34b34000c785acfdffff08000000b810000000 }

condition:
	$a0
}

        
