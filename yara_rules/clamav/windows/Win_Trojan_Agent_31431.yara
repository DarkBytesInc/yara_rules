rule Win_Trojan_Agent_31431
{
strings:
	$a0 = { 5f28fc217d2d71e86fb937ddbbfe09fcddc064c5241fd971156c4151028ad8703678f4c08b535ede1f0ffae5cd21f56934e979d479af8129a7f8f610755cbe9e8385f58b7068fe3d2197838f30ccdb4b129ad057df59d236c92082b932adf6633e50b3a9ec912c582291de73c457e21a260e1b98c3ced913ae4efeeb07738873e8a518adb44ed24c027bc9433e8df281d5a518143ed6 }

condition:
	$a0
}

        