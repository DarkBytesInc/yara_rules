rule Win_Trojan_Small_3239
{
strings:
	$a0 = { 9b1652985001a1bf34191e7b1001cd26b271f7ba108ce7ee2d41da035525361b8d1e1a7b994dfeda9845fee2c93eda7a10349a088d25430465253e6ebc8e269f148e2e9f28522ce1bb6bdae4106b1ee510ab }

condition:
	$a0
}

        
