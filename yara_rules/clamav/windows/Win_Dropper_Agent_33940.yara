rule Win_Dropper_Agent_33940
{
strings:
	$a0 = { 841ce0ecfb62704b42d6c0e0d4b81baf362ce0dfd09ae0df0b1384e1deecdd3b8a7e3b201fa622517d3b17e4bccccc70226bfc6321e1bc15c82eacaa657b5ef6bcdb175b402a1932d23a2520f92d1370c60f6ddff352d483d13a6bfce20c2e3f0f89a0a1f7d52c0c8f3c7a0951d6ad7a9183ab108c96e956878de46a6badaf8d }

condition:
	$a0
}

        
