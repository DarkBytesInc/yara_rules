rule Win_Dropper_Delf_563
{
strings:
	$a0 = { 09642cf5594110e9ebe943e941850629e941e9e9e969c1e6f9f6f66ca97c05ae2cf1e9e8e9e9642cf159646cf9f7f6f659642cfd5943e943e9622cf559c1f9c6f6f6622cf559c1dec6f6f6646cf9f7f6f659c142f9f6f662d9642cf9c138c1f6f6622cf969310b7c0c642cf959625cf9b1d90629e9c1c1c3f6f662a16aa8ebb3ebe9e9e9622cf9c127c3f6f6c20a642cf959625cf9b1 }

condition:
	$a0
}

        