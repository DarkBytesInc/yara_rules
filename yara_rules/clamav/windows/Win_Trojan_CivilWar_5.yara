rule Win_Trojan_CivilWar_5
{
strings:
	$a0 = { 5d81ed03018db68c01bf0001a5a58d969001b41acd218d968201b44ecd2172538d96ae01b8023dcd21724493b90400b43f8d968c01cd2180be8f015674 }

condition:
	$a0
}

        
