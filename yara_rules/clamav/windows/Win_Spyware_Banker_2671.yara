rule Win_Spyware_Banker_2671
{
strings:
	$a0 = { 85509c38b7f2c7ea625846d8f37678bd157bd4256fdfd98b58a7bb77f2a6af5f0ba46a731b49624e5ebbe57be4cff6c9864b9021a5f645af5dd1d72769d237ae50d3d63c6c56de24e7949df9e894a0bd9cc4c941a105f2ca5a4fa613d00d39ee609c }

condition:
	$a0
}

        
