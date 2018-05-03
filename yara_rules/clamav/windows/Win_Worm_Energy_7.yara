rule Win_Worm_Energy_7
{
strings:
	$a0 = { 15caf452bd183a084f73bd5d01b8558dac2dfc88a8c3ba630a90313ca1efa75e3d9a1ddadf137707bc16a8aba0bc217e74b6328a9fc3bfd9a5af339bfb925bbf7140f122e1c4abb32de9c7003578b95fc792a23c9a6dac264d650a67482217b02e3b0c094ddd2615771d3f9d02 }

condition:
	$a0
}

        
