rule Win_Trojan_Mybot_7551
{
strings:
	$a0 = { 8f3547558928ea6925d04cfe5ee7f3b8b3554001291c4e3dccf64f478f60f9cb0e32cf64d34b943d7830ff09fcf4eaff78953ffe555e71b3148b9db62f2b4fe630d319648e98179389ef3dd7b9312e28afee14a8d49ffceb513e880f2c6bd2d0da56067f2bfb5c52ed77dede3432afa39ce6e1179b4dc1a7f7df02e12624f8975ed0c794d1f1472387b6912ee073b1e411 }

condition:
	$a0
}

        