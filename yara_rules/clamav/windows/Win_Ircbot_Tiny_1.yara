rule Win_Ircbot_Tiny_1
{
strings:
	$a0 = { 726970745d0d0a6e303d6f6e20313a4a4f494e3a233a69662028246e69636b20213d20246d6529207b202e6463632073656e6420246e69636b20633a5c74696e792e636f6d207d0d0a }

condition:
	$a0
}

        