rule Win_Trojan_PSW_9
{
strings:
	$a0 = { bf6bc645c0b9c645c1f7c645c280c645c39ec645c4fbc645c592c645c613c645c741c645c826885dc9e83b080000598b4dfc508d45a450e85f0000008d45a450 }

condition:
	$a0
}

        
