rule Win_Trojan_LookSpy_1
{
strings:
	$a0 = { 9adfc2de1d8ecd244db6f6cccee0f0ce412c7f124d7036de37b848767cc47a1aa89e2c97cf0fb49e7a54d5a352ac63071db7d77b6c4d7c155c4d38529c7e1b5ddfe2b2b2f4b2bf7dcb9f073595d1f5db913ee4b4b9876193612a1c10572474e3775f5a9bc47afdee9fe26f1543 }

condition:
	$a0
}

        
