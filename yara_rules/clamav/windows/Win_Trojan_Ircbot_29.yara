rule Win_Trojan_Ircbot_29
{
strings:
	$a0 = { 4696ca037baef810c2927c111dbefbde947964c9f878293880f58cd5c7c6ce69daaae07c9e9c4b7725db39fd21048eccf0774f8953a26c335143ff67372e8cabce1fdf2b8eba50f4cd33b3c661b4a6c0c9194c95aa2ac70582f05bd16d3bfed633d47dbeeae73e23ca06633453f8010b14ab39200cb0002b0cb72865029992278b6a54515134c082a6c2a978a4c461374849b2b129e9 }

condition:
	$a0
}

        