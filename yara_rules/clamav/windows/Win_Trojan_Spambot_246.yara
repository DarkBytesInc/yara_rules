rule Win_Trojan_Spambot_246
{
strings:
	$a0 = { 6c5fe4a11683545b8f2fe3aef17791d47720a85855ffff3ffc646e0dde18d801da0209bbc6df54e2fdd2ac173147817721e81bfffffffffe45cccd6860e7265db76938b3615f2e9e1d62d93c9b8b54c521ad1cd412232901feffffb7638e520c2039d8631cd783d29d0b1ae00e1e }

condition:
	$a0
}

        
