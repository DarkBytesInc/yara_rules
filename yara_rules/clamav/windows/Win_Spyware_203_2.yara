rule Win_Spyware_203_2
{
strings:
	$a0 = { d571a1ad5e267ad0ffaf5a6d07adcf474f42525a976127b55cba39912356485381c0d535f0eb9b03412862de80413283316f423a14f633a088fce3c6f93924373b29a44465facd6ece0d9d5a6d0792032c7998a8be3b6fa0f30444ea63108a67dd7a734717c1e394fcd6a3fbf1d5ab58dc3f667c5d95e469b2547043456218f5f27b95fb2f069950cbb5025f626159 }

condition:
	$a0
}

        