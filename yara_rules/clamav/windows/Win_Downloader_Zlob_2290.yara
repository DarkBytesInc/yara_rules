rule Win_Downloader_Zlob_2290
{
strings:
	$a0 = { 847d8a208a66431edb9945db29f5dacab6bcc91972b7a73d49c8adfd087575b3ed644e20139712db1b5d710a828a7cb3a5e035bc354dad6a7cffce6e78e02f23a4de4947cf33ab0920ca3792b3c2195cb935141fbd11ab912254 }

condition:
	$a0
}

        
