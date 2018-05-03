rule Win_Tool_DoS_7
{
strings:
	$a0 = { 7aeaceb55e8a15c36d275a5bac8481c4c0a6ac164df8badc154b5d1b87cb186d3a05f8897bef493dd6a53411198b16504453e8442a3fd20785f60f8eb70b6eee2d7d84b9eb45eac084c0fd84a20654895c21a72c4da62a286353 }

condition:
	$a0
}

        
