rule Win_Dropper_Delf_738
{
strings:
	$a0 = { 02468f0046b35b8c56bf250246a5c4065b8c8c8c178b8b8b1e065b8c8c8c5b8c56bb00062b8c8c8c08a389367f08ce578c8c8c86366808ce538c8c8c8a399f250046a588cb250246a5a09d250046a588cb2508cb89250246a5595a58002e8f270086938b8b8b004b7b004b9f08cb9f008372ca376702c14d0831838b4d008237bb4d70519336a125005ea525024167250241650046b3 }

condition:
	$a0
}

        