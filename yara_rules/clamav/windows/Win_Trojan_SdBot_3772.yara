rule Win_Trojan_SdBot_3772
{
strings:
	$a0 = { 95cd7ed1d4f3feedbe37912191bb7c1d986f35915a330765b0835d6c1eb82fce80fcdbb161afc6b1a0cf9a44a9f61781ca0e6ded788fff73ca7faeee8bbe9f7a5615d3251a71486e4057845d0666cc22a66c2f1aa27f91afa79a24c4cd00172b87fdafc1633979cf364dae89456b }

condition:
	$a0
}

        
