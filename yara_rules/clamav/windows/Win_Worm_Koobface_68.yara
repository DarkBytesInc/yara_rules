rule Win_Worm_Koobface_68
{
strings:
	$a0 = { 83ec3885ca7413b80c000000506a003eff1530504800584875f2e818000000e802000000eb77648b4018ff3089208b4004f71083c438c3558bec83ec48b8300000000344244c894424502bc0c9c3c24b00450052004e0045004c00330032002e0064006c }

condition:
	$a0
}

        