rule Win_Trojan_Hupigon_84
{
strings:
	$a0 = { 4b63945d6e9c55c9e5cc72ef92c0cf814d307033f61af0ca867c5dc546f66acd663609479fcb4db5b129cc52aef512aaa732d30b7ed8a9501e3735b0dccf59ab2ec86de9d6dafd001d312a7359bb04fb1778095739c8aad6eefa2db55cf8f6ed848edcd335d19d051e4964 }

condition:
	$a0
}

        
