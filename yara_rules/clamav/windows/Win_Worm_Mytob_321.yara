rule Win_Worm_Mytob_321
{
strings:
	$a0 = { e6ea62398d96622e44fd9e7a4b3a0f2407f5bf78a0ff3616c543b190561d8df7be557a09e89276486fbd8fdb7a2bf626c3724e3e76cc719a7c9ce4bab66e217fb965ca4a2ced2aead325f404cbb4fa81b92558e52627c4e773f269bcd351534c }

condition:
	$a0
}

        
