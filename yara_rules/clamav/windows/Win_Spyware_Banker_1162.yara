rule Win_Spyware_Banker_1162
{
strings:
	$a0 = { f5fffff864951fbc53db93efb7db8775bdb423966924e5ef5bbdfffaff60e91d0dbf91563b1175aca69f6777b2dc0861ffff7ffa9994a0705bf71c900f071daad5f595ae9f7909782696cca952f1ff1ffeffddc4c6561d48640c }

condition:
	$a0
}

        
