rule Win_Trojan_Spambot_94
{
strings:
	$a0 = { 60ccffffffff763d633e614586f5068e3cfd780368bbd48609a03ea8a42daa41c134e0efa508ff83ffffd54f8af5559eb14f438c02710a7b0c9ec779a2bd24e89315d9c4f5ffffff982a7a9ea30432d231a9ebf8e836ff3685cb3a5266b4ca97ff89fd22ffff7f0673967af38d1b }

condition:
	$a0
}

        
