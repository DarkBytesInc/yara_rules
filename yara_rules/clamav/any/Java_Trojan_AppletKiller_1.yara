rule Java_Trojan_AppletKiller_1
{
strings:
	$a0 = { 252ab20013b6001b2a1202b600154c2bc700092a03b50014b12a1103e82bb8001968b50014b10000000100480000001e00070000002e00070033000e00340012003500170034001800360024002d000100680036000100410000004c00040001000000242ab4001fc7001f2abb000d592ab70010b5001f2ab4001f100ab6 }

condition:
	$a0
}

        