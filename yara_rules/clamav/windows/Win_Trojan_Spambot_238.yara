rule Win_Trojan_Spambot_238
{
strings:
	$a0 = { cbcd80bf88fcffffffffe9107d99495bf15721d6e23fadb9f8fa04748bb2eaa441ee9bbfff86223d912affffffff7b03c0b50af73222d3f49da3fa92cd748cc27a9a9b9f6725e52920e995d0b679ffffffff872b7568175b5d66216f1bc67c13fa6849eaba5e924d231d25bc7ae1 }

condition:
	$a0
}

        
