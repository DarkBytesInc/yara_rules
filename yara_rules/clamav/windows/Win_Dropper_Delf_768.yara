rule Win_Dropper_Delf_768
{
strings:
	$a0 = { 72e47c30b5a4e47ce4e4e464fc95f4e5e51f246fb0dd5fece49be4e4175fec54171ff4e6e5e554175fe85472e472e4115fe054fcf4f5e5e5115fe054fccdf5e5e5171ff4e6e5e554fc71f4e5e511d4175ff4fcabfce5e5115ff464acba6fbf175ff454114ff42cd4b5a4e4fcfcf2e5e511dc19db9a229ae4e4e4115ff4fc56f2e5e5f1b9175ff454114ff42cd4b5a4e4fcd9f2e5e511 }

condition:
	$a0
}

        