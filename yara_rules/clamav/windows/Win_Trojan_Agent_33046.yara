rule Win_Trojan_Agent_33046
{
strings:
	$a0 = { 6c636f6d6d5c4575646f726120dbdb175c0be9644c696e1b637572216ed84b65b3743f2e6731b47fa37d546875142b626972645c50723c5a3b422bd973e36f7a0a82dbf646c213587665460c742e498b357e7333e953686f7747665320c8f68fff534d545020456d1d41646472137363d8df3e446973704b79204e616d65273f6694dbed779864320f485453d827eccb13494d412350 }

condition:
	$a0
}

        