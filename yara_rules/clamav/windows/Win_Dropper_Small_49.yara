rule Win_Dropper_Small_49
{
strings:
	$a0 = { 7669636500534f46df7e5bfe54574152455c4d72326f66745c571f646f7773f6bfb5ff5c43757272656e7456293f6f6e5c52756e000d0a01feff87fd002e3235350320476f6f676c652e636f6d20235375706155fbd62b5969746531260ea2 }

condition:
	$a0
}

        