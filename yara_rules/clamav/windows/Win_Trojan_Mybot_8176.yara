rule Win_Trojan_Mybot_8176
{
strings:
	$a0 = { cd289cdcf642b1ffcb6131943f910b396458f1a132d43aa664b6d51fcc9aa51a7c7b3968fc029f8f66c6b7037c311ef7c7c78b05c3648ce7549f638206235285501ac9f5b7aef35523a446e654b835663c8c324a2a253a872fde46cd44a781169a7ac9c73abc534f46391bd5aa5e0af0c85131a98ec7acf84aa43e388bf29c2e079e77ca99244378070cfdae90f7bb0e78 }

condition:
	$a0
}

        