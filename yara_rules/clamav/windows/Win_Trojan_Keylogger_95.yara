rule Win_Trojan_Keylogger_95
{
strings:
	$a0 = { d914e34a75dd5ce85d96bad20fa15158377b39f8501770adf101347617e64d78e128c02f984b033f4d19e23e6d3c14c18d46846256255861607e1de9226563a3d09f2858814c14bb0fc8b3fc50a6f76ff58afbac1142f653298bf566e8fe95981706a16965ff3813dd1e31b83f7ee7809dace46a1ccda3b8f5a71e9366467875772e7c5a0417dce8cf576bbd }

condition:
	$a0
}

        