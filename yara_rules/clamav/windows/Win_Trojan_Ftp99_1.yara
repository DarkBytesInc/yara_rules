rule Win_Trojan_Ftp99_1
{
strings:
	$a0 = { 50313d412c2a2e2a2e2a2e2a0d0a0d0a5b555345523d6861636b636974795d0d0a50617373776f72643d0d0a486f6d654469723d633a5c0d0a416c77617973416c6c6f774c6f67696e3d5945530d0a416363657373313d613a5c2c52574d43444c45500d0a416363657373323d623a }

condition:
	$a0
}

        