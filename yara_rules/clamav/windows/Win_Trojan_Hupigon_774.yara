rule Win_Trojan_Hupigon_774
{
strings:
	$a0 = { 9641a844c8014b7502252421bec67fdeaaed483feb2fa97f887724479c01715690eadcf83ef8faef8541640040e084b24df941e39bf0dd5881c0cccb9a3491a26fbcb0e0e9461eb04da1a9958bf0e123510670d8aef17c6a49f0adadbc07fc }

condition:
	$a0
}

        
