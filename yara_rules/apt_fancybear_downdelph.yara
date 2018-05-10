rule APT_fancybear_Downdelph_magic : Bootkit{
	  meta:
    author = "Marc Salinas @Bondey_m"
    description = "APT28 downdelph magic string"
    severity = "10"
    type = "Advanced Persistent Threat"
	strings:
		$str1 = " :3 "
	condition:
		$str1 at 0
}



rule APT_fancybear_Downdelph_MBR : Bootkit{
	  meta:
    author = "Marc Salinas @Bondey_m"
    description = "APT_fancybear_Downdelph_MBR"
    severity = "10"
    type = "Advanced Persistent Threat"
	strings:
		$s1 = { 20 3A 33 20 } //string " :3 "
	condition:
		$s1 at 411  //posición 0x19b
}