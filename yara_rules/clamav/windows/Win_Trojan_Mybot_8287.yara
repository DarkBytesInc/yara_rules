rule Win_Trojan_Mybot_8287
{
strings:
	$a0 = { 2f6effadd0523d72ef86e3994bd013a9639ee25e7645ab2ea6e869ff979325f30ed302639212c7b4f973d9eb210fe14644d58371bbc39371914e5619373c0e075034ceb093c7230a6b250c6ef4b30d26dd71c6d9af1782638dd39ffbe7ae7cd12eb9daeb2079f23d70ebd3800336d24010cea0ccf4a939f587b4987a4ef41802382e75664c02a1cddb479227 }

condition:
	$a0
}

        