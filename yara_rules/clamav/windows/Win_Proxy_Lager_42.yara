rule Win_Proxy_Lager_42
{
strings:
	$a0 = { 6b65324b601e92b21f7dc2ff5a7bed10e9f1949f8588828a1e4ab201ec2b77c3c87afac7ce737483509f07e555ad2ccc0155c2fcc466b0b7300f2721b0bdb28b15451bcfa27c }

condition:
	$a0
}

        
