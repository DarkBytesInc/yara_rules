rule Win_Trojan_Aimbot_19
{
strings:
	$a0 = { 7935402db179ad5f7e76a1e2d873c4caf4771d0316294390fdbfb6aafdef24fde897efe6eea429f0ba6facf7ce42e28adae696bda18e79f6993a0bef10701409c2a9529b5b393c367a47c9679a3ab8809c01a75192ae6bf83ff69fa3f034af6fc0c07f1dbdedb83fec3dc62e464dc10e2553f780f91d3a7f453ac7 }

condition:
	$a0
}

        
