rule Win_Trojan_Mybot_5081
{
strings:
	$a0 = { e4f3d593e876a71a74498c34f09c0cbe41f6cabb1adbd0dba11c78eca88e8f5327fdf716f8167f36078d4b31bd7762ed9fc4a4ce57cdf61356a10e9f977f742172dea20ae2c9fac70d8b2b9a75242163f12cdd49339c2338238c }

condition:
	$a0
}

        
