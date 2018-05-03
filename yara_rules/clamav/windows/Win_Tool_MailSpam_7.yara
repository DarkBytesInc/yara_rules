rule Win_Tool_MailSpam_7
{
strings:
	$a0 = { 88000021f77670110101655874727f656d654d61696ce0360af4f1da554c02f3f0f402105d205dd42c58f4f1db554c03 }

condition:
	$a0
}

        
