rule Win_Trojan_Patched_147
{
strings:
	$a0 = { 2e70646200[0-64]bf761d807c8d735e8a0e84c9740b8d460550ffd783c610ebef8d73468b7b4203fb83c7466a00546a406a2057b8cf1a807cffd0b918000000f3a4589d61ebaa8dc0faff8bff558bec53 }

condition:
	$a0
}

        
