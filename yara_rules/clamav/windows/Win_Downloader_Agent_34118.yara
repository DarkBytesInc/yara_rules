rule Win_Downloader_Agent_34118
{
strings:
	$a0 = { eb82e10d33c0ea3938b6c8fd68c800c0a16741fbc7850500e90100016ee1c15e79ccfdff75085a041ba06b8b550c8b12f816485c100cff521c5fff4df879019d88e83d398e0dc88d66e803002ccfd705f88945f0e4f4bb17c721f0ece8c84b4e0020837de4000f848673c0363ae4e0c78a0b700bbae4ff12e000746db05f7460e0d0e0ff92715c575d94d055 }

condition:
	$a0
}

        