rule Unix_Tool_13426_1
{
strings:
	$a0 = { eb115e31c9b12080340e0fe2fa80340e0f56c3e8eaffffffe41d513ecf87490882510a5c82115cbf365fc28fe7e6f0f0f0206d6661207c67 }

condition:
	$a0
}

        
