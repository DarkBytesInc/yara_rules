rule Win_Dropper_Agent_34997
{
strings:
	$a0 = { 71f9b15ba97ee5a670471533b50804e9ed3397301b95eb7e53bac3fe05826d4115dac13de78f1b0e9b3a7e0543854a88d89ec2d5c8f59394065cd1c44c142a593a2a443eea50f963eff128722bf611fc1abfd5ec27652fe76d43d01e3c03f0f3b5a196cf07d79947326ca9f9d972697d56abe72a8bb0ce51c89d9993fc716abf9ca9f5c64de1237a2bd40322 }

condition:
	$a0
}

        