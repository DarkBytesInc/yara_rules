rule Win_Worm_StrationQR_1
{
strings:
	$a0 = { e00000c0be1cd040008bdeadad50ad97b280a4b680ff1373f933c9ff13731633c0ff137321b68041b010ff1312c073fa753eaaebe0e876ce000002f683d90175 }

condition:
	$a0
}

        
