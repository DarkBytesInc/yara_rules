rule Win_Trojan_Hupigon_242
{
strings:
	$a0 = { e294590234ec8db02f9d5979b7c5c5b182c7ff63e11304ac2ef3c4dcf9f88abbcccb9ec80390d2ad5eff8d61f7ef8b597def192f16d7ab381fc6430a3869ed13f275309ddbf374ad02c1b7132a0464d05fc37f96a8224ec3ca5abaa7689985eb21cedf3ec3213c523d }

condition:
	$a0
}

        
