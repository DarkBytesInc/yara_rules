rule Win_Spyware_Banker_1182
{
strings:
	$a0 = { 765663410357d682da3ea04e873e5aa676d6aa3fa164a4b087663bd084e33c156d198028da0b2e461184a49a486cec96bffc2aafe3aaf924cff4e9163da05f21d8b1fd1188566528e94412687cddab6ea00973b2c9142c7d48e2 }

condition:
	$a0
}

        