rule Win_Spyware_Banker_5826
{
strings:
	$a0 = { b952f685554b0aea8a84642904396a904555b48a8a83db47b7ef2dacc64890138f27afeca701426a2b4f3e228cfd8dfcddfa1bb4f7677a9dd7bef70f6d75bf637cecf87585eb0e90a3d9bbd7278cc17c3ef8e1bd76e67f7c7686dfc36e3dbadb6133ddabb9358cde248c4668823916c78349f92f7b85509502528dabb948d674 }

condition:
	$a0
}

        