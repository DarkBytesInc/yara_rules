rule Win_Trojan_Small_3840
{
strings:
	$a0 = { 481cd30dc061dbbe286b23f081a8c85af4c5f2dcc11ae15a0c28f4ce3afa5f0bbfcd6b6847cf617cf43bea2046ab49b02321a50010912bfc896a9ca7e4dd6497feb5cb9d38b3b906ae85eec7d9e5592fe25d3c7b0fdc55bad7896ccdf4bfb71a31c7052fdda150dedf }

condition:
	$a0
}

        
