rule Win_Spyware_Banker_2735
{
strings:
	$a0 = { 97f89eada0982211bf95dc0ef3e768fd7f3a605e32836220e66046c2a1c1ebd81c786b9ab6eb2a76215bc93d96b4439a87c9109049256b125d7ff27548b37fa4c87e0724eed9102c709bf267ae9a }

condition:
	$a0
}

        
