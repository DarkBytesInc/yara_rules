rule Win_Ransomware_Locky_31471
{
strings:
	$a0 = { 558bec5156578d45??50ff15[4]50ff15[4]8bf085f6741b837d??027c15ff7604ff15[4]59568bf8ff15[4]eb0233ff8bc75f5ec9c3 }

condition:
	$a0
}

        
