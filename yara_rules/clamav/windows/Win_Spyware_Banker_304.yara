rule Win_Spyware_Banker_304
{
strings:
	$a0 = { 38d6551ccec62c9f6a2a9d386a95918e5f0fbcdc19c9f4dadc3de1ad63d649f6e23cbe02cd007112c528bcc54c85412d2b3750256e34dba933d4ea4296aa7571e596525bb49e1503df517ac4432c0badb936bd7bab3b0b376fdb7473b68a0906853e36cb319da9605709c5d5044fc43b85167024a43d23d7b61cbcd9667529b1f63efd26f092df42f51d47bc365e514972a5fbf4 }

condition:
	$a0
}

        