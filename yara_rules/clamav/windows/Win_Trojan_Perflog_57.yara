rule Win_Trojan_Perflog_57
{
strings:
	$a0 = { 802900d6330000008000000294460bcac72d14331d3509002000000062706b686b2e646c6c1e421559088922201a664f42ce620808602048fa01f41e8c404448187db0347a159a46b166a2a1ac5b07311c173306416651 }

condition:
	$a0
}

        