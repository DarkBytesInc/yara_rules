rule Win_Spyware_Banker_2072
{
strings:
	$a0 = { 139c2da426cbc6adbca75c40ac1f0ed277333f982eeabeedecb8fc9c5697a78283e9a5d4e7b67c013bde852abe47fd78ed5098b92d003fc8afd53fbb458cd96fc9b160a1274cceb8a949231b3db690e2d11272e953abd94eb5c01d7524ae980cca0785f7faf93c8ccebd9b22ae66d28eb2168b899ae3f7b4f361befa02fe42f6 }

condition:
	$a0
}

        
