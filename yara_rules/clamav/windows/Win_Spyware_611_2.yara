rule Win_Spyware_611_2
{
strings:
	$a0 = { ea28612dfc5347c1ae40afb9241dbbc2828e53c7f9a82a95ea40c7adb754bc393dbe502e82c0f2c5f9a8622f15bfc71f1656bcb9ee41afd1828a54c7f9286cc3fe53c751b754bcb99f1dbbc202daecd1ea4b6fa5fe28788cfe53c71b1156bc39d104af }

condition:
	$a0
}

        
