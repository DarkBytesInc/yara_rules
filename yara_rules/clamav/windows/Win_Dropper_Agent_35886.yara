rule Win_Dropper_Agent_35886
{
strings:
	$a0 = { 33f766bbc0f32bfb66b85ddb2bc32bcc2bd68bd48bf58bfe2bf803f466ba82278bde418bf203d98bd5e803000000c214002bc803d15b535d66b9962a81c32e0000002bef33f99990532bfb32353a1e41008bd48bd533f28bc603f9c38d0dfc13410066bf5ec3669903d887c92bc803cd8d2d55d4400066b9889abec603000087 }

condition:
	$a0
}

        