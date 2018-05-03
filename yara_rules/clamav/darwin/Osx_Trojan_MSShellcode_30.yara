rule Osx_Trojan_MSShellcode_30
{
strings:
	$a0 = { 3ba00fff3bc00fff379df0027fdcf0514180fff0381df0677fc3f3783881eff838a00fff38ddf08144ffff027cc63279a361eff82c1b496a4082ffd43881effc }

condition:
	$a0
}

        
