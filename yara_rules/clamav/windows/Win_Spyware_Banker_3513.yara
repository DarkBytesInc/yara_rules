rule Win_Spyware_Banker_3513
{
strings:
	$a0 = { eaeb72734808801134175eeca2a06501e715a9279b69e06c76adad431cc1cf8c5d30fcd04eee97397517422a48e04acc807c194710f151437b77fbd2dbb3662a3daa9ed1ad7e68a95c445eac41eb422c88b019e23603031e1f3c37506aaad868 }

condition:
	$a0
}

        